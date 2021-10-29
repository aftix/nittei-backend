#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_sync_db_pools;

use rocket_sync_db_pools::diesel;

#[database("nittei")]
pub struct PSQL(diesel::PgConnection);

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(PSQL::fairing())
        .mount("/", routes![])
}
