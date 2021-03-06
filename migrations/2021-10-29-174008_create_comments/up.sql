-- Your SQL goes here
CREATE TABLE comments(
    cid INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    uid INT NOT NULL,
    tid INT NOT NULL,
    content TEXT NOT NULL,
    FOREIGN KEY (uid) REFERENCES users (uid),
    FOREIGN KEY (tid) REFERENCES times (tid)
);
