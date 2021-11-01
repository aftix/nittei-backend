-- This file should undo anything in `up.sql`
DROP TABLE tokens;
CREATE TABLE tokens(
    uid INT NOT NULL PRIMARY KEY,
    session VARCHAR(128) NOT NULL,
    expires TIMESTAMP,
    FOREIGN KEY (uid) REFERENCES users (uid)
);
