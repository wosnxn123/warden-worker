-- Email verification tokens.
-- Issued at registration time and when the user clicks "resend verification email".
-- Consumed (deleted) once the user follows the link.
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user ON email_verification_tokens(user_id);
