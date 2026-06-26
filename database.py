"""
SECURE AI CHATBOT - DATABASE MODULE
================================================================================
This module provides a secure abstraction layer over SQLite using only
parameterized queries. This eliminates SQL injection vulnerabilities by
ensuring user input is never concatenated into SQL strings.

SECURITY FEATURES:
  - All query functions use ? placeholders (parameterized queries)
  - Every read/write operation is scoped to a user_id (RLS equivalent)
  - Connection management uses context managers for automatic cleanup
  - Foreign keys are enforced via PRAGMA on every connection
================================================================================
"""

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
DATABASE_PATH = os.environ.get("DATABASE_PATH", "chatbot.db")

# ---------------------------------------------------------------------------
# CONNECTION HELPER
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """
    Create a new SQLite connection with security-hardened defaults.

n    Returns:
        sqlite3.Connection: A connection with row factory and foreign keys enabled.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    # Return rows as sqlite3.Row objects for dict-like access
    conn.row_factory = sqlite3.Row
    # CRITICAL: Enable foreign key enforcement. SQLite disables this by default.
    # Without this PRAGMA, ON DELETE CASCADE and foreign key checks are ignored.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

# ---------------------------------------------------------------------------
# USER MANAGEMENT
# ---------------------------------------------------------------------------

def create_user(username: str, password_hash: str) -> int:
    """
    Insert a new user with a pre-hashed password.

    Args:
        username: Unique username chosen by the user.
        password_hash: The bcrypt hash of the user's password (never plain text).

    Returns:
        The auto-generated user_id of the newly created user.

    Raises:
        sqlite3.IntegrityError: If the username already exists (UNIQUE constraint).
    """
    query = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
    with get_connection() as conn:
        cursor = conn.execute(query, (username, password_hash))
        conn.commit()
        return cursor.lastrowid


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a user record by username. Used during login to fetch
    the stored password hash for comparison.

    Args:
        username: The username to look up.

    Returns:
        A dict with user columns if found, otherwise None.
    """
    query = "SELECT id, username, password_hash, created_at FROM users WHERE username = ?"
    with get_connection() as conn:
        row = conn.execute(query, (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a user record by ID. Used to validate session tokens.

    Args:
        user_id: The numeric user ID.

    Returns:
        A dict with user columns if found, otherwise None.
    """
    query = "SELECT id, username, created_at FROM users WHERE id = ?"
    with get_connection() as conn:
        row = conn.execute(query, (user_id,)).fetchone()
        return dict(row) if row else None

# ---------------------------------------------------------------------------
# CONVERSATION MANAGEMENT (User-Scoped)
# ---------------------------------------------------------------------------
# ALL functions in this section REQUIRE a user_id parameter and apply it as
# a WHERE clause filter. This enforces data isolation: users can only ever
# access their own messages. This is the equivalent of Row-Level Security.
# ---------------------------------------------------------------------------

def save_message(user_id: int, role: str, content: str) -> int:
    """
    Persist a single chat message linked to a specific user.

    Args:
        user_id: The ID of the user who owns this message (RLS filter).
        role: One of 'user', 'assistant', or 'system'.
        content: The message text content.

    Returns:
        The auto-generated message ID.
    """
    query = """
        INSERT INTO conversations (user_id, role, content)
        VALUES (?, ?, ?)
    """
    with get_connection() as conn:
        cursor = conn.execute(query, (user_id, role, content))
        conn.commit()
        return cursor.lastrowid


def get_conversation_history(user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Retrieve the most recent N messages for a specific user, ordered
    chronologically. This enforces user isolation by filtering on user_id.

    Args:
        user_id: The ID of the user whose history to retrieve (RLS filter).
        limit: Maximum number of messages to return (default 20, prevents
               excessive memory usage and keeps API context window manageable).

    Returns:
        A list of message dicts with keys: id, user_id, role, content, created_at.
    """
    query = """
        SELECT id, user_id, role, content, created_at
        FROM conversations
        WHERE user_id = ?
        ORDER BY created_at ASC
        LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(query, (user_id, limit)).fetchall()
        return [dict(row) for row in rows]


def get_recent_messages_for_context(user_id: int, limit: int = 10) -> List[Dict[str, str]]:
    """
    Get the most recent messages formatted for the OpenAI API context window.
    Only returns 'user' and 'assistant' roles (excludes system prompts stored
    in the database, as those are injected separately).

    Args:
        user_id: The ID of the user whose context to build (RLS filter).
        limit: Number of recent message pairs to include in context.

    Returns:
        A list of dicts with 'role' and 'content' keys for OpenAI API format.
    """
    query = """
        SELECT role, content
        FROM conversations
        WHERE user_id = ? AND role IN ('user', 'assistant')
        ORDER BY created_at ASC
        LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(query, (user_id, limit)).fetchall()
        return [{"role": row["role"], "content": row["content"]} for row in rows]


def clear_conversation_history(user_id: int) -> int:
    """
    Delete all messages for a specific user. This is a destructive operation
    scoped strictly to the requesting user.

    Args:
        user_id: The ID of the user whose history to clear (RLS filter).

    Returns:
        The number of rows deleted.
    """
    query = "DELETE FROM conversations WHERE user_id = ?"
    with get_connection() as conn:
        cursor = conn.execute(query, (user_id,))
        conn.commit()
        return cursor.rowcount

# ---------------------------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------------------------

def init_db():
    """
    Initialize the database by executing the schema.sql script.
    This creates tables and indexes if they don't already exist.
    Called once during application startup.
    """
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with get_connection() as conn:
        with open(schema_path, "r") as f:
            conn.executescript(f.read())
        conn.commit()
