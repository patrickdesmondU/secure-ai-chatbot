-- =============================================================================
-- SECURE AI CHATBOT - DATABASE SCHEMA
-- =============================================================================
-- This schema enforces Row-Level Security (RLS) equivalent isolation by:
-- 1. Linking every conversation message to a specific user via FOREIGN KEY
-- 2. Creating composite indexes for fast user-scoped queries
-- 3. Using CASCADE DELETE to clean up user data on account deletion
-- =============================================================================

-- ---------------------------------------------------------------------------
-- USERS TABLE
-- ---------------------------------------------------------------------------
-- Stores user credentials with bcrypt-hashed passwords.
-- Never store plain-text passwords. The password_hash field stores the
-- bcrypt hash output which includes the salt internally.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- CONVERSATIONS TABLE
-- ---------------------------------------------------------------------------
-- Stores chat messages with strict user isolation via user_id foreign key.
-- The 'role' column uses a CHECK constraint to only allow valid OpenAI roles.
-- Every query against this table MUST include WHERE user_id = ? to enforce
-- the equivalent of Row-Level Security.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS conversations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    role        TEXT NOT NULL CHECK(role IN ('user', 'assistant', 'system')),
    content     TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Enforce referential integrity: messages belong to a valid user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- INDEXES
-- ---------------------------------------------------------------------------
-- These indexes are critical for performance and security:
-- idx_conversations_user_id: Ensures user-scoped queries are O(log n) instead
--   of O(n), preventing slow queries that could become DoS vectors.
-- idx_conversations_created_at: Supports efficient chronological ordering.
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_conversations_user_id
    ON conversations(user_id);

CREATE INDEX IF NOT EXISTS idx_conversations_created_at
    ON conversations(created_at);

CREATE INDEX IF NOT EXISTS idx_conversations_user_created
    ON conversations(user_id, created_at);

-- ---------------------------------------------------------------------------
-- SQLITE PRAGMAS FOR PRODUCTION
-- ---------------------------------------------------------------------------
-- Enable foreign key enforcement (SQLite disables it by default for
-- backward compatibility). Without this, ON DELETE CASCADE will NOT fire.
-- ---------------------------------------------------------------------------
PRAGMA foreign_keys = ON;
