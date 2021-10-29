-- Your SQL goes here
CREATE TABLE friends(
    uid1 INT NOT NULL PRIMARY KEY,
    uid2 INT NOT NULL,
    FOREIGN KEY (uid1) REFERENCES users (uid),
    FOREIGN KEY (uid2) REFERENCES users (uid)
);
