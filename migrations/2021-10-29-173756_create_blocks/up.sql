-- Your SQL goes here
CREATE TABLE blocks(
    uid INT NOT NULL PRIMARY KEY,
    annoyance INT NOT NULL,
    FOREIGN KEY (uid) REFERENCES users (uid),
    FOREIGN KEY (annoyance) REFERENCES users (uid)
);
