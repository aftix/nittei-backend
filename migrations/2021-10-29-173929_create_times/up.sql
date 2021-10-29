-- Your SQL goes here
CREATE TABLE times(
    tid INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    uid INT NOT NULL,
    privacy INT NOT NULL,
    start TIMESTAMP NOT NULL,
    duration INT NOT NULL,
    description TEXT,
    title VARCHAR(50) NOT NULL,
    FOREIGN KEY (uid) REFERENCES users (uid)
);