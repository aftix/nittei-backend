use chrono::NaiveDateTime;
use diesel::Queryable;

// User table row
#[derive(Debug, Queryable)]
pub struct SQLUser {
    pub uid: i32,
    pub username: String,
    pub passwordhash: String,
    pub joindate: NaiveDateTime,
    pub donator: Option<i32>,
    pub email: String,
    pub verified: Option<i32>,
    pub postdefault: Option<i32>,
    pub uimode: Option<i32>,
    pub authlevel: Option<i32>,
}

use crate::schema::users;
// For inserting a new user into users table
#[derive(Debug, Insertable)]
#[table_name = "users"]
pub struct NewUser {
    pub username: String,
    pub passwordhash: String,
    pub joindate: NaiveDateTime,
    pub email: String,
}

use crate::schema::verifycodes;
// For inserting and retrieving a new verification code into verifycodes table
#[derive(Debug, Insertable, Queryable)]
#[table_name = "verifycodes"]
pub struct VerifyCode {
    pub uid: i32,
    pub codehash: String,
    pub setat: NaiveDateTime,
}
