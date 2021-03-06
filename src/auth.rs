use crate::consts;
use crate::sql::*;
use crate::util::{Admin, IPRateLimiter, Moderator, Ron, User};
use crate::{RateLimiter, SessionSecret, PSQL};
use argon2::{verify_encoded, Config};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use email_address_parser::EmailAddress;
use lettre::{SendmailTransport, Transport};
use lettre_email::EmailBuilder;
use nittei_common::auth::*;
use passwords::{analyzer, scorer};
use rand::{Rng, SeedableRng};
use rocket::State;
use std::time::{SystemTime, UNIX_EPOCH};

#[options("/auth/register")]
pub async fn register_opt() -> &'static str {
    ""
}

#[post("/auth/register", data = "<req>")]
pub async fn register(
    secret: &State<SessionSecret>,
    conn: PSQL,
    mut ip_limiter: IPRateLimiter<'_>,
    limiter: &State<RateLimiter>,
    req: RegisterRequest,
) -> Ron<RegisterResponse> {
    use crate::schema::users::dsl::*;
    use crate::schema::verifycodes::dsl::*;

    ip_limiter.set_state(limiter.inner());

    // Check that email is ok
    if !EmailAddress::is_valid(&req.email, None) {
        return Ron::new(RegisterResponse::InvalidEmail);
    }

    // If username is longer than 30 characters, fail
    if req.username.len() > 30 || req.username.is_empty() {
        return Ron::new(RegisterResponse::InvalidUsername);
    }

    // Check user availability
    let name = req.username.clone();
    let results = conn
        .run(|c| users.filter(username.eq(name)).load::<SQLUser>(c))
        .await;

    // Username exists, fail
    if results.is_ok() && !results.unwrap().is_empty() {
        return Ron::new(RegisterResponse::UsernameTaken);
    }

    // Check password security
    let analyzed = analyzer::analyze(&req.password);
    if analyzed.length() < 8 {
        return Ron::new(RegisterResponse::WeakPassword);
    }
    let scored = scorer::score(&analyzed);
    if scored < 70.0 {
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
        email: req.email.clone(),
    };

    let result = conn
        .run(move |c| {
            diesel::insert_into(users)
                .values(&new_user)
                .get_result::<SQLUser>(c)
        })
        .await;
    // Check if user was created successfully
    if result.is_err() {
        return Ron::new(RegisterResponse::EmailTaken);
    }
    let result = result.unwrap();

    // New user success! Make a session key just like on login for QOL
    let now = SystemTime::now();
    let now: u64 = now
        .duration_since(UNIX_EPOCH)
        .expect("Shouldn't happen! Time went backwards!")
        .as_secs();
    let claim = Claim {
        exp: now + 5 * 60,
        sub: req.email.clone(),
        user: result.username.clone(),
        iat: now,
        auth: nittei_common::auth::AuthLevel::User,
    };
    let jwt = AuthToken::new(&claim, &secret.inner().0);
    if jwt.is_err() {
        return Ron::new(RegisterResponse::InvalidRequest);
    }

    // Email verification
    let verification_code: String = Rng::gen::<u128>(&mut rng).to_string();
    let email_msg = EmailBuilder::new()
        .to((&req.email, &req.username))
        .from(consts::EMAIL_ADDRESS)
        .subject(consts::EMAIL_SUBJECT)
        .text(format!(
            "{}{}/{}/{}",
            consts::EMAIL_BODY,
            consts::VERIFY,
            &req.username,
            &verification_code
        ))
        .build()
        .unwrap();
    let mut mailer = SendmailTransport::new();
    if mailer.send(email_msg.into()).is_err() {
        error!("Mail failed to send to {}!", &req.email);
    }

    // Put verification code into table
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let now = NaiveDateTime::from_timestamp(now as i64, 0);

    let salt: String = Rng::gen::<u128>(&mut rng).to_string();
    let code_hash =
        argon2::hash_encoded(verification_code.as_bytes(), salt.as_bytes(), &config).unwrap();

    let verifycode = VerifyCode {
        uid: result.uid,
        codehash: code_hash,
        setat: now,
    };

    let res = conn
        .run(move |c| {
            diesel::insert_into(verifycodes)
                .values(&verifycode)
                .load::<VerifyCode>(c)
        })
        .await;
    if res.is_err() {
        error!("Failed entering user verification code into table!");
    }

    ip_limiter.success = true;
    Ron::new(RegisterResponse::Success(jwt.unwrap(), claim))
}

#[options("/auth/login")]
pub async fn login_opt() -> &'static str {
    ""
}

#[post("/auth/login", data = "<req>")]
pub async fn login(
    secret: &State<SessionSecret>,
    conn: PSQL,
    mut ip_limiter: IPRateLimiter<'_>,
    limiter: &State<RateLimiter>,
    req: LoginRequest,
) -> Ron<LoginResponse> {
    use crate::schema::users::dsl::*;

    ip_limiter.set_state(limiter.inner());

    // Get user from users table
    let name = req.email.clone();
    let results = conn
        .run(|c| users.filter(email.eq(name)).load::<SQLUser>(c))
        .await;

    // Username does not exist
    if results.is_err() {
        return Ron::new(LoginResponse::EmailInvalid);
    }
    // Get the only user from the vec, if there is one
    let my_user = results.unwrap();
    let my_user = my_user.get(0);
    if my_user.is_none() {
        return Ron::new(LoginResponse::EmailInvalid);
    }
    let my_user = my_user.unwrap();

    // Verify that password hash matches
    let verification = verify_encoded(&my_user.passwordhash, req.password.as_bytes());

    if verification.is_err() {
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
        sub: my_user.email.clone(),
        user: my_user.username.clone(),
        iat: now,
        auth: nittei_common::auth::AuthLevel::from(my_user.authlevel.unwrap_or(0)),
    };
    let jwt = AuthToken::new(&claim, &secret.inner().0);
    if jwt.is_err() {
        return Ron::new(LoginResponse::InvalidRequest);
    }

    ip_limiter.success = true;
    Ron::new(LoginResponse::Success(jwt.unwrap(), claim))
}

#[options("/auth/renew")]
pub async fn renew_opt() -> &'static str {
    ""
}

#[get("/auth/renew")]
pub async fn renew_admin(secret: &State<SessionSecret>, admin: Admin) -> Ron<RenewResponse> {
    // Request guard verifies we have an admin. Make a new claim for an admin session.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time moved backwards")
        .as_secs();
    let claim = Claim {
        exp: now + 5 * 60,
        sub: admin.email,
        user: admin.username,
        iat: now,
        auth: nittei_common::auth::AuthLevel::Admin,
    };
    let jwt = AuthToken::new(&claim, &secret.inner().0);
    if jwt.is_err() {
        return Ron::new(RenewResponse::InvalidRequest);
    }

    Ron::new(RenewResponse::Success(jwt.unwrap()))
}

#[get("/auth/renew", rank = 2)]
pub async fn renew_mod(secret: &State<SessionSecret>, moderator: Moderator) -> Ron<RenewResponse> {
    // Request guard verifies we have an admin. Make a new claim for an admin session.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time moved backwards")
        .as_secs();
    let claim = Claim {
        exp: now + 5 * 60,
        sub: moderator.email,
        user: moderator.username,
        iat: now,
        auth: nittei_common::auth::AuthLevel::Mod,
    };
    let jwt = AuthToken::new(&claim, &secret.inner().0);
    if jwt.is_err() {
        return Ron::new(RenewResponse::InvalidRequest);
    }

    Ron::new(RenewResponse::Success(jwt.unwrap()))
}

#[get("/auth/renew", rank = 3)]
pub async fn renew_user(secret: &State<SessionSecret>, user: User) -> Ron<RenewResponse> {
    // Request guard verifies we have an admin. Make a new claim for an admin session.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time moved backwards")
        .as_secs();
    let claim = Claim {
        exp: now + 5 * 60,
        sub: user.email,
        user: user.username,
        iat: now,
        auth: nittei_common::auth::AuthLevel::User,
    };
    let jwt = AuthToken::new(&claim, &secret.inner().0);
    if jwt.is_err() {
        return Ron::new(RenewResponse::InvalidRequest);
    }

    Ron::new(RenewResponse::Success(jwt.unwrap()))
}

#[options("/auth/persist_request")]
pub async fn persist_req_opt() -> &'static str {
    ""
}

#[post("/auth/persist_request", data = "<req>")]
pub async fn persist_req(
    http_user: User,
    conn: PSQL,
    mut ip_limiter: IPRateLimiter<'_>,
    limiter: &State<RateLimiter>,
    req: PersistRequest,
) -> Ron<PersistResponse> {
    use crate::schema::tokens::dsl::*;
    use crate::schema::users::dsl::*;

    ip_limiter.set_state(limiter.inner());

    if http_user.email != req.email {
        return Ron::new(PersistResponse::InvalidRequest);
    }

    // Get user from users table
    let name = req.email.clone();
    let results = conn
        .run(|c| users.filter(email.eq(name)).load::<SQLUser>(c))
        .await;

    // Username does not exist
    if results.is_err() {
        return Ron::new(PersistResponse::InvalidUser);
    }
    // Get the only user from the vec, if there is one
    let my_user = results.unwrap();
    let my_user = my_user.get(0);
    if my_user.is_none() {
        return Ron::new(PersistResponse::InvalidUser);
    }
    let my_user = my_user.unwrap();

    // Verify that password hash matches
    let verification = verify_encoded(&my_user.passwordhash, req.password.as_bytes());

    if verification.is_err() {
        return Ron::new(PersistResponse::InvalidRequest);
    }

    let verification = verification.unwrap();

    if !verification {
        return Ron::new(PersistResponse::InvalidPassword);
    }

    // Create a new random salt
    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    let salt: String = Rng::gen::<u128>(&mut rng).to_string();
    let config = Config::default();

    // Create a new PersistToken
    let token = PersistToken {
        session: Rng::gen::<u64>(&mut rng),
        token: Rng::gen::<u64>(&mut rng),
    };
    let hash = argon2::hash_encoded(token.token.to_string().as_bytes(), salt.as_bytes(), &config);
    if hash.is_err() {
        return Ron::new(PersistResponse::InvalidRequest);
    }

    let token_ins = NewToken {
        uid: my_user.uid,
        session: token.session.to_string(),
        tokenhash: hash.unwrap(),
        expires: None,
    };

    let res = conn
        .run(move |c| {
            diesel::insert_into(tokens)
                .values(&token_ins)
                .load::<Token>(c)
        })
        .await;
    if res.is_err() {
        return Ron::new(PersistResponse::InvalidRequest);
    }

    ip_limiter.success = true;
    Ron::new(PersistResponse::Success(token))
}

#[options("/auth/persist_login")]
pub async fn persist_login_opt() -> &'static str {
    ""
}

#[post("/auth/persist_login", data = "<req>")]
pub async fn persist_login(
    secret: &State<SessionSecret>,
    conn: PSQL,
    mut ip_limiter: IPRateLimiter<'_>,
    limiter: &State<RateLimiter>,
    req: PersistLoginRequest,
) -> Ron<PersistLoginResponse> {
    use crate::schema::tokens::dsl::*;
    use crate::schema::users::dsl::*;

    ip_limiter.set_state(limiter.inner());

    // Get the right session for the given token
    let my_session = req.token.session.to_string();
    let my_email = req.email.clone();
    let my_tokens = conn
        .run(move |c| {
            tokens
                .inner_join(users)
                .filter(email.eq(my_email).and(session.eq(my_session)))
                .load::<(Token, SQLUser)>(c)
        })
        .await;

    if my_tokens.is_err() {
        return Ron::new(PersistLoginResponse::InvalidSession);
    }
    let my_tokens = my_tokens.unwrap();
    if my_tokens.len() != 1 {
        return Ron::new(PersistLoginResponse::InvalidSession);
    }

    // Verify the token, session is good
    let verification = verify_encoded(
        &my_tokens[0].0.tokenhash,
        req.token.token.to_string().as_bytes(),
    );

    if verification.is_err() || !verification.unwrap() {
        // Token is wrong, delete the remember me token
        let res = conn
            .run(move |c| diesel::delete(tokens.filter(tid.eq(my_tokens[0].0.tid))).execute(c))
            .await;
        if res.is_ok() {
            return Ron::new(PersistLoginResponse::InvalidToken);
        } else {
            return Ron::new(PersistLoginResponse::Lockout);
        }
    }

    // Token is verified! Make JWT
    let now = SystemTime::now();
    let now: u64 = now
        .duration_since(UNIX_EPOCH)
        .expect("Shouldn't happen! Time went backwards!")
        .as_secs();
    let claim = Claim {
        exp: now + 5 * 60,
        sub: my_tokens[0].1.email.clone(),
        user: my_tokens[0].1.username.clone(),
        iat: now,
        auth: nittei_common::auth::AuthLevel::from(my_tokens[0].1.authlevel.unwrap_or(0)),
    };
    let jwt = AuthToken::new(&claim, &secret.inner().0);
    if jwt.is_err() {
        return Ron::new(PersistLoginResponse::Lockout);
    }

    ip_limiter.success = true;
    Ron::new(PersistLoginResponse::Success(jwt.unwrap(), claim))
}
