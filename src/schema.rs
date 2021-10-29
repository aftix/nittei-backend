table! {
    blocks (uid) {
        uid -> Int4,
        annoyance -> Int4,
    }
}

table! {
    comments (cid) {
        cid -> Int4,
        uid -> Int4,
        tid -> Int4,
        content -> Text,
    }
}

table! {
    friends (uid1) {
        uid1 -> Int4,
        uid2 -> Int4,
    }
}

table! {
    resetcodes (uid) {
        uid -> Int4,
        codehash -> Varchar,
    }
}

table! {
    times (tid) {
        tid -> Int4,
        uid -> Int4,
        privacy -> Int4,
        start -> Timestamp,
        duration -> Int4,
        description -> Nullable<Text>,
        title -> Varchar,
    }
}

table! {
    tokens (uid) {
        uid -> Int4,
        session -> Varchar,
        tokenhash -> Varchar,
        expires -> Nullable<Timestamp>,
    }
}

table! {
    users (uid) {
        uid -> Int4,
        username -> Varchar,
        passwordhash -> Varchar,
        joindate -> Timestamp,
        donator -> Nullable<Int4>,
        email -> Varchar,
        verified -> Nullable<Int4>,
        postdefault -> Nullable<Int4>,
        uimode -> Nullable<Int4>,
    }
}

joinable!(comments -> times (tid));
joinable!(comments -> users (uid));
joinable!(resetcodes -> users (uid));
joinable!(times -> users (uid));
joinable!(tokens -> users (uid));

allow_tables_to_appear_in_same_query!(
    blocks,
    comments,
    friends,
    resetcodes,
    times,
    tokens,
    users,
);
