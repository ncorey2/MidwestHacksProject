PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    file TEXT NOT  NULL,
    line TEXT NOT NULL,
    scanner TEXT NOT NULL,
    evidence TEXT
)