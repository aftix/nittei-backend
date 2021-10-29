use crate::sql::*;
use crate::util::Ron;
use crate::{SessionSecret, PSQL};
use argon2::{verify_encoded, Config};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use nittei_common::auth::*;
use passwords::{analyzer, scorer};
use rand::{Rng, SeedableRng};
use rocket::State;
use std::time::{SystemTime, UNIX_EPOCH};

#[post("/auth/register", data = "<req>")]
pub async fn register(
    secret: &State<SessionSecret>,
    conn: PSQL,
    req: RegisterRequest,
) -> Ron<RegisterResponse> {
    use crate::schema::users::dsl::*;

    // Check user availability
    let name = req.username.clone();
    let results = conn
        .run(|c| users.filter(username.eq(name)).load::<User>(c))
        .await;

    // Username exists, fail
    if let Ok(_) = results {
        return Ron::new(RegisterResponse::UsernameTaken);
    }

    // Check password security
    let analyzed = analyzer::analyze(&req.password);
    if analyzed.length() < 8 {
        return Ron::new(RegisterResponse::WeakPassword);
    }
    let scored = scorer::score(&analyzed);
    if scored < 80.0 {
        return Ron::new(RegisterResponse::WeakPassword);
    }

    // Create a new random salt
    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let salt: String = Rng::gen::<u128>(&mut rng).to_string();
    let config = Config::default();
    let hash = argon2::hash_encoded(req.password.as_bytes(), salt.as_bytes(), &config).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went Backwards");

    let new_user = NewUser {
        username: req.username.clone(),
        passwordhash: hash,
        joindate: NaiveDateTime::from_timestamp(
            now.as_secs() as i64,
            (now.as_nanos() - 1000000000 * now.as_secs() as u128) as u32,
        ),
        email: req.email,
    };

    let result = conn
        .run(move |c| {
            diesel::insert_into(users)
                .values(&new_user)
                .get_result::<User>(c)
        })
        .await;
    // Check if user was created successfully
    if let Err(_) = result {
        return Ron::new(RegisterResponse::EmailTaken);
    }

    // New user success! Make a session key just like on login for QOL
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
        return Ron::new(RegisterResponse::InvalidRequest);
    }
    Ron::new(RegisterResponse::Success(jwt.unwrap()))
}

#[post("/auth/login", data = "<req>")]
pub async fn login(
    secret: &State<SessionSecret>,
    conn: PSQL,
    req: LoginRequest,
) -> Ron<LoginResponse> {
    use crate::schema::users::dsl::*;
    // Get user from users table
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
