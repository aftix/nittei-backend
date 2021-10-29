use chrono::NaiveDateTime;
use diesel::Queryable;

// User table row
#[derive(Debug, Queryable)]
pub struct User {
    pub uid: i32,
    pub username: String,
    pub passwordhash: String,
    pub joindate: NaiveDateTime,
    pub donator: Option<i32>,
    pub email: String,
    pub verified: Option<i32>,
    pub postdefault: Option<i32>,
    pub uimode: Option<i32>,
}
