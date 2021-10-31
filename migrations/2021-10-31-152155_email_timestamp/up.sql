-- Your SQL goes here
ALTER TABLE resetcodes ADD COLUMN setat TIMESTAMP NOT NULL;
CREATE TABLE verifycodes(
    uid INT NOT NULL PRIMARY KEY,
    codehash VARCHAR(128) NOT NULL,
    setat TIMESTAMP NOT NULL,
    FOREIGN KEY (uid) REFERENCES users (uid)
);
