#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_sync_db_pools;

use rand::{Rng, SeedableRng};
use rocket_sync_db_pools::diesel;

// Connection to PostgreSQL
#[database("nittei")]
pub struct PSQL(diesel::PgConnection);

// The secret for the sessions
pub struct SessionSecret(String);

#[launch]
fn rocket() -> _ {
    // Generate session secret from CSRNG
    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let secret: SessionSecret = SessionSecret(Rng::gen::<u128>(&mut rng).to_string());

    rocket::build()
        .manage(secret)
        .attach(PSQL::fairing())
        .mount("/", routes![])
}
