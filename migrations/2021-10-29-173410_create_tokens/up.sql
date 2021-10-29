-- Your SQL goes here
CREATE TABLE tokens(
    uid INT NOT NULL PRIMARY KEY,
    session VARCHAR(128) NOT NULL,
    tokenhash VARCHAR(128) NOT NULL,
    expires TIMESTAMP,
    FOREIGN KEY (uid) REFERENCES users (uid)
);
