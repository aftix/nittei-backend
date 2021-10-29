use core::fmt::Debug;
use rocket::http::{ContentType, Status};
use rocket::request::{self, FromRequest};
use rocket::response::{Responder, Response, Result};
use rocket::Request;
use ron;
use serde::Serialize;
use std::io::Cursor;
use std::net::SocketAddr;

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
pub struct SourceIP(pub SocketAddr);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for &'r SourceIP {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let ip = req.remote();
        if ip == None {
            return request::Outcome::Failure((Status::BadRequest, ()));
        }

        request::Outcome::Success(req.local_cache(|| SourceIP(ip.unwrap())))
    }
}
