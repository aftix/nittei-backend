-- Your SQL goes here
CREATE TABLE resetcodes(
    uid INT NOT NULL PRIMARY KEY,
    codehash VARCHAR(128) NOT NULL,
    FOREIGN KEY (uid) REFERENCES users (uid)
);
