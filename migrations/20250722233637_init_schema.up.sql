-- Up migrations

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    user_token_hash TEXT NOT NULL,
    username_last_changed TIMESTAMPTZ NOT NULL DEFAULT now(),
    role TEXT NOT NULL DEFAULT 'user',
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    bio TEXT,
    profile_picture_url TEXT
);

CREATE TABLE IF NOT EXISTS pastes (
    token TEXT PRIMARY KEY NOT NULL CHECK(token != ''),
    content TEXT NOT NULL,
    css TEXT,
    timestamp TIMESTAMPTZ NOT NULL,
    edit_timestamp TIMESTAMPTZ NOT NULL,
    user_id TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS paste_collaborators (
    paste_token TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (paste_token, user_id),
    FOREIGN KEY (paste_token) REFERENCES pastes(token) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS friendships (
    user_id1 TEXT NOT NULL,
    user_id2 TEXT NOT NULL,
    PRIMARY KEY (user_id1, user_id2),
    FOREIGN KEY (user_id1) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id2) REFERENCES users(user_id) ON DELETE CASCADE,
    CHECK (user_id1 < user_id2)
);

CREATE TABLE IF NOT EXISTS friend_requests (
    request_id SERIAL PRIMARY KEY,
    sender_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    receiver_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (sender_id, receiver_id),
    CHECK (sender_id != receiver_id)
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    notification_type TEXT NOT NULL,
    related_user_id TEXT REFERENCES users(user_id),
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes

CREATE INDEX IF NOT EXISTS idx_pastes_fts_content_tsv ON pastes_fts USING gin(content_tsv);
CREATE INDEX IF NOT EXISTS idx_pastes_token ON pastes(token);
CREATE INDEX IF NOT EXISTS idx_pastes_user_id ON pastes(user_id);
CREATE INDEX IF NOT EXISTS idx_pastes_timestamp ON pastes(timestamp);
CREATE INDEX IF NOT EXISTS idx_pastes_edit_timestamp ON pastes(edit_timestamp);
CREATE INDEX IF NOT EXISTS idx_paste_collaborators_paste_token ON paste_collaborators(paste_token);
CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned);
