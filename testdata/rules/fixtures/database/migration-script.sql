ALTER TABLE users ADD COLUMN last_login timestamp;
CREATE INDEX idx_users_last_login ON users (last_login);
