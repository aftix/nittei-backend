#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_sync_db_pools;
#[macro_use]
extern crate diesel;

use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

// Connection to PostgreSQL
#[database("nittei")]
pub struct PSQL(diesel::PgConnection);

// structs for diesel and such
pub mod schema;
pub mod sql;

// The secret for the sessions
pub struct SessionSecret(String);

pub mod util;

// API for User Authentication
pub mod auth;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    pub timeout: i64,
    pub lastattempt: u128,
    pub attempts: i32,
}

pub struct RateLimiter {
    pub map: Mutex<HashMap<IpAddr, RateLimit>>,
}

#[launch]
fn rocket() -> _ {
    // Generate session secret from CSRNG
    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let secret: SessionSecret = SessionSecret(Rng::gen::<u128>(&mut rng).to_string());

    let map: HashMap<IpAddr, RateLimit> = HashMap::new();
    let map = Mutex::new(map);
    let limiter = RateLimiter { map };

    rocket::build()
        .manage(secret)
        .manage(limiter)
        .attach(PSQL::fairing())
        .mount("/", routes![auth::login, auth::register])
}
