use crate::{RateLimit, RateLimiter};
use core::fmt::Debug;
use rocket::http::{ContentType, Status};
use rocket::request::{self, FromRequest};
use rocket::response::{Responder, Response, Result};
use rocket::Request;
use rocket::State;
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
        if let Err(_) = text {
            return Err(Status::UnprocessableEntity);
        }
        let text = text.unwrap();
        Ok(Response::build()
            .header(ContentType::Plain)
            .sized_body(text.len(), Cursor::new(text))
            .finalize())
    }
}

// Request Guard for getting the source IP
pub struct SourceIP(pub IpAddr);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r SourceIP {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let ip = req.client_ip();
        if ip == None {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }

        request::Outcome::Success(req.local_cache(|| SourceIP(ip.unwrap())))
    }
}

pub fn rate_limit(limiter: &State<RateLimiter>, ip: &SourceIP) -> Option<RateLimit> {
    // Rate limit
    let limit = {
        let guard = limiter.inner().map.lock().unwrap();
        let ip = ip.0;
        let get = guard.get(&ip);
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
        return None;
    }

    Some(limit)
}

// Insert the updated rate limit into the hashmap
pub fn update_limit(mut limit: RateLimit, ip: &SourceIP, limiter: &State<RateLimiter>) {
    limit.attempts += 1;
    if limit.attempts == 3 {
        limit.timeout = 100; // Start at 1 second
    } else if limit.attempts > 3 {
        limit.timeout *= 2;
    }

    if limit.timeout > 100 * 60 * 5 {
        // max out at 5 minute
        limit.timeout = 100 * 60 * 5;
    }

    {
        let mut gaurd = limiter.inner().map.lock().unwrap();
        gaurd.insert(ip.0, limit);
    }
}
