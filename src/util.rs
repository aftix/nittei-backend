use crate::{RateLimit, RateLimiter, SessionSecret};
use core::fmt::Debug;
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{ContentType, Status},
    request::{self, FromRequest},
    response::{Responder, Response, Result},
    Data, Request,
};
use ron;
use serde::Serialize;
use std::io::Cursor;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

// Responder that automatically serializes in RON form
#[derive(Debug, Serialize)]
pub struct Ron<T: Serialize + Debug> {
    inner: T,
}

impl<T: Serialize + Debug> Ron<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<'r, 'o: 'r, T: Serialize + Debug> Responder<'r, 'o> for Ron<T> {
    fn respond_to(self, _req: &'r Request<'_>) -> Result<'o> {
        let text = ron::to_string(&self.inner);
        if text.is_err() {
            return Err(Status::UnprocessableEntity);
        }
        let text = text.unwrap();
        Ok(Response::build()
            .header(ContentType::Plain)
            .sized_body(text.len(), Cursor::new(text))
            .finalize())
    }
}

// Rate limiting guard
pub struct IPRateLimiter<'r> {
    pub success: bool, // if true, remove rate limit from table and don't update
    limit: RateLimit,
    state: Option<&'r RateLimiter>,
    ip: IpAddr,
}

#[rocket::async_trait]
impl<'r, 'o> FromRequest<'r> for IPRateLimiter<'o> {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Get current rate limit from state
        let map = req.rocket().state::<RateLimiter>();
        if map.is_none() {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }
        let map = map.unwrap();
        let limit = {
            let guard = map.map.lock().unwrap();
            let ip = req.client_ip();
            if ip.is_none() {
                return request::Outcome::Failure((Status::BadRequest, ()));
            }
            let get = guard.get(&ip.unwrap());
            if let Some(timeout) = get {
                timeout.clone()
            } else {
                RateLimit {
                    lastattempt: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time moved backwards")
                        .as_millis(),
                    timeout: 0,
                    attempts: 0,
                }
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time moved backwards")
            .as_millis();
        let elapsed = now - limit.lastattempt;
        if elapsed < limit.timeout as u128 {
            return request::Outcome::Failure((Status::UnprocessableEntity, ()));
        }

        request::Outcome::Success(IPRateLimiter {
            success: false,
            limit,
            state: None,
            ip: req.client_ip().unwrap(),
        })
    }
}

impl<'r> Drop for IPRateLimiter<'r> {
    fn drop(&mut self) {
        // Drop limit on success
        if self.success {
            if let Some(limiter) = self.state {
                let mut guard = limiter.map.lock().unwrap();
                guard.remove_entry(&self.ip);
            }
            return;
        }

        // On failure increase attempt number
        self.limit.attempts += 1;
        match self.limit.attempts {
            3 => self.limit.timeout = 100,
            d if d > 3 => self.limit.timeout *= 2,
            _ => {}
        }

        if self.limit.timeout > 100 * 60 * 5 {
            // max out at 5 minute
            self.limit.timeout = 100 * 60 * 5;
        }

        // Insert back into state
        if let Some(limiter) = self.state {
            let mut guard = limiter.map.lock().unwrap();
            guard.insert(self.ip, self.limit.clone());
        }
    }
}

impl<'r> IPRateLimiter<'r> {
    pub fn set_state(&mut self, state: &'r RateLimiter) {
        self.state = Some(state);
    }
}

// Fairing for allowing CORS
pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "CORS Header",
            kind: Kind::Response,
        }
    }

    async fn on_request(&self, _: &mut Request<'_>, _: &mut Data<'_>) {}

    async fn on_response<'r>(&self, _: &'r Request<'_>, resp: &mut Response<'r>) {
        resp.set_raw_header("Access-Control-Allow-Origin", "*");
        resp.set_raw_header(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        );
        resp.set_raw_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    }
}

// Request guard for verifying user
pub struct User {
    pub username: String,
    pub email: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Get JWT from Authorization header
        let auth = req.headers().get_one("Authorization");
        if auth.is_none() {
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let auth = auth.unwrap();

        let parts: Vec<&str> = auth.split(' ').collect();
        if parts.len() != 2 {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }
        if parts[0] != "Bearer" {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }

        // Authenticate JWT
        let jwt = parts[1];
        let token = nittei_common::auth::AuthToken::from_jwt(jwt);
        let secret = req.rocket().state::<SessionSecret>();
        if secret.is_none() {
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let secret = secret.unwrap();
        let claim = token.authenticate(&secret.0);
        if claim.is_none() {
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let claim = claim.unwrap();

        // exp field automatically checked by jsonwebtoken

        request::Outcome::Success(User {
            email: claim.sub,
            username: claim.user,
        })
    }
}

// Request guard for verifying moderator
pub struct Moderator {
    pub username: String,
    pub email: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Moderator {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Get JWT from Authorization header
        let auth = req.headers().get_one("Authorization");
        if auth.is_none() {
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let auth = auth.unwrap();

        let parts: Vec<&str> = auth.split(' ').collect();
        if parts.len() != 2 {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }
        if parts[0] != "Bearer" {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }

        // Authenticate JWT
        let jwt = parts[1];
        let token = nittei_common::auth::AuthToken::from_jwt(jwt);
        let secret = req.rocket().state::<SessionSecret>();
        if secret.is_none() {
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let secret = secret.unwrap();
        let claim = token.authenticate(&secret.0);
        if claim.is_none() {
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let claim = claim.unwrap();

        // exp field automatically checked by jsonwebtoken

        // If user isn't a moderator or admin, forward
        if claim.auth == nittei_common::auth::AuthLevel::User {
            return request::Outcome::Forward(());
        }

        request::Outcome::Success(Moderator {
            email: claim.sub,
            username: claim.user,
        })
    }
}

// Request guard for verifying admin
pub struct Admin {
    pub username: String,
    pub email: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Admin {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        // Get JWT from Authorization header
        let auth = req.headers().get_one("Authorization");
        if auth.is_none() {
            println!("No header");
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let auth = auth.unwrap();

        let parts: Vec<&str> = auth.split(' ').collect();
        if parts.len() != 2 {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }
        if parts[0] != "Bearer" {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }

        // Authenticate JWT
        let jwt = parts[1];
        let token = nittei_common::auth::AuthToken::from_jwt(jwt);
        let secret = req.rocket().state::<SessionSecret>();
        if secret.is_none() {
            println!("No secret");
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let secret = secret.unwrap();
        let claim = token.authenticate(&secret.0);
        if claim.is_none() {
            println!("bad claim");
            return request::Outcome::Failure((Status::Unauthorized, ()));
        }
        let claim = claim.unwrap();

        // exp field automatically checked by jsonwebtoken

        // If user isn't a admin, forward
        if claim.auth == nittei_common::auth::AuthLevel::User
            || claim.auth == nittei_common::auth::AuthLevel::Mod
        {
            return request::Outcome::Forward(());
        }

        request::Outcome::Success(Admin {
            email: claim.sub,
            username: claim.user,
        })
    }
}
