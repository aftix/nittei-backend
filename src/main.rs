#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_sync_db_pools;
#[macro_use]
extern crate diesel;

use rand::{Rng, SeedableRng};

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

#[launch]
fn rocket() -> _ {
    // Generate session secret from CSRNG
    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let secret: SessionSecret = SessionSecret(Rng::gen::<u128>(&mut rng).to_string());

    rocket::build()
        .manage(secret)
        .attach(PSQL::fairing())
        .mount("/", routes![auth::login, auth::register])
}
