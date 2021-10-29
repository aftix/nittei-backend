use crate::sql::*;
use crate::util::Ron;
use crate::{SessionSecret, PSQL};
use argon2::verify_encoded;
use diesel::prelude::*;
use nittei_common::auth::*;
use rocket::State;
use std::time::{SystemTime, UNIX_EPOCH};

#[post("/auth/login", data = "<req>")]
pub async fn login(
    secret: &State<SessionSecret>,
    conn: PSQL,
    req: LoginRequest,
) -> Ron<LoginResponse> {
    use crate::schema::users::dsl::*;
    // Check username availability
    let name = req.username.clone();
    let results = conn
        .run(|c| users.filter(username.eq(name)).load::<User>(c))
        .await;

    // Username does not exist
    if let Err(_) = results {
        return Ron::new(LoginResponse::UsernameInvalid);
    }
    // Get the only user from the vec
    let my_user = results.unwrap();
    let my_user = my_user.iter().next().unwrap();

    // Verify that password hash matches
    let verification = verify_encoded(&my_user.passwordhash, req.password.as_bytes());

    if let Err(_) = verification {
        return Ron::new(LoginResponse::InvalidRequest);
    }

    let verification = verification.unwrap();

    if !verification {
        return Ron::new(LoginResponse::PasswordWrong);
    }

    // Password verified, make JWT that expires in 5 minutes
    let now = SystemTime::now();
    let now: u64 = now
        .duration_since(UNIX_EPOCH)
        .expect("Shouldn't happen! Time went backwards!")
        .as_secs();
    let claim = Claim {
        exp: now + 5 * 60,
        sub: req.username,
        iat: now,
    };
    let jwt = AuthToken::new(&claim, &secret.inner().0);
    if let Err(_) = jwt {
        return Ron::new(LoginResponse::InvalidRequest);
    }
    Ron::new(LoginResponse::Success(jwt.unwrap()))
}
