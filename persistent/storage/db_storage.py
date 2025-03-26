# storage/db_storage.py
import sqlite3
import threading
import time
import os
import logging
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ChatDatabase:
    """
    SQLite database adapter for the chat service.
    Handles persistent storage of users, messages, and system state.
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.initialize_db()
        logger.info(f"Initialized database at {db_path}")
        
    @contextmanager
    def get_connection(self):
        """Context manager for database connections with proper locking."""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
                
    def initialize_db(self):
        """Create database tables if they don't exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            ''')
            
            # Messages table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (sender) REFERENCES users (username),
                FOREIGN KEY (recipient) REFERENCES users (username)
            )
            ''')
            
            # Replication log table for operation-based replication
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS replication_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL,
                parameters TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                applied INTEGER NOT NULL DEFAULT 0
            )
            ''')
            
            # System state table for leader election and configuration
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            ''')
            
            # Create indexes for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages (recipient)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_read ON messages (read)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_replication_log_applied ON replication_log (applied)')
            
            conn.commit()
            
    # User management methods
    def user_exists(self, username):
        """Check if a user exists in the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
            return cursor.fetchone() is not None
            
    def create_user(self, username, hashed_password):
        """Create a new user in the database."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)',
                (username, hashed_password, timestamp)
            )
            conn.commit()
            return True
            
    def verify_user(self, username, hashed_password):
        """Verify user credentials."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT password FROM users WHERE username = ?',
                (username,)
            )
            result = cursor.fetchone()
            if result and result['password'] == hashed_password:
                return True
            return False
            
    def delete_user(self, username):
        """Delete a user and all their messages."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Check if user has unread messages
            cursor.execute(
                'SELECT COUNT(*) as count FROM messages WHERE recipient = ? AND read = 0',
                (username,)
            )
            result = cursor.fetchone()
            if result and result['count'] > 0:
                return False, "Cannot delete account with unread messages"
                
            # Delete user's messages
            cursor.execute('DELETE FROM messages WHERE sender = ? OR recipient = ?', 
                           (username, username))
            
            # Delete the user
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
            return True, "Account deleted successfully"
            
    def list_users(self, pattern):
        """List users matching a pattern."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # SQLite's LIKE is case-insensitive by default
            # Convert * to % for SQL LIKE pattern
            sql_pattern = pattern.replace('*', '%')
            cursor.execute('SELECT username FROM users WHERE username LIKE ?', (sql_pattern,))
            return [row['username'] for row in cursor.fetchall()]
            
    # Message management methods
    def queue_message(self, sender, recipient, content):
        """Store a new message in the database."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO messages (sender, recipient, content, timestamp, read) VALUES (?, ?, ?, ?, 0)',
                (sender, recipient, content, timestamp)
            )
            conn.commit()
            return timestamp
            
    def get_unread_message_count(self, username):
        """Get count of unread messages for a user."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COUNT(*) as count FROM messages WHERE recipient = ? AND read = 0',
                (username,)
            )
            result = cursor.fetchone()
            return result['count'] if result else 0
            
    def get_unread_messages(self, username, count):
        """Get unread messages for a user and mark them as read."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT id, sender, content, timestamp 
                   FROM messages 
                   WHERE recipient = ? AND read = 0
                   ORDER BY timestamp ASC
                   LIMIT ?''',
                (username, count)
            )
            messages = [dict(row) for row in cursor.fetchall()]
            
            # Mark retrieved messages as read
            if messages:
                message_ids = [msg['id'] for msg in messages]
                placeholders = ','.join('?' for _ in message_ids)
                cursor.execute(
                    f'UPDATE messages SET read = 1 WHERE id IN ({placeholders})',
                    message_ids
                )
                conn.commit()
                
            return messages
            
    def delete_read_messages(self, username, delete_info):
        """Delete read messages for a user."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if delete_info.upper() == "ALL":
                cursor.execute(
                    'SELECT COUNT(*) as count FROM messages WHERE recipient = ? AND read = 1',
                    (username,)
                )
                result = cursor.fetchone()
                count = result['count'] if result else 0
                
                cursor.execute(
                    'DELETE FROM messages WHERE recipient = ? AND read = 1',
                    (username,)
                )
                conn.commit()
                return count
            else:
                try:
                    num = int(delete_info)
                    cursor.execute(
                        '''DELETE FROM messages WHERE id IN (
                           SELECT id FROM messages 
                           WHERE recipient = ? AND read = 1
                           ORDER BY timestamp ASC
                           LIMIT ?
                        )''',
                        (username, num)
                    )
                    count = cursor.rowcount
                    conn.commit()
                    return count
                except ValueError:
                    return 0
                    
    # Replication and system state methods
    def log_operation(self, operation, parameters):
        """Add an operation to the replication log."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO replication_log (operation, parameters, timestamp, applied) VALUES (?, ?, ?, 1)',
                (operation, parameters, timestamp)
            )
            conn.commit()
            return cursor.lastrowid
            
    def get_unapplied_operations(self, limit=1000):
        """Get operations that have not been applied yet."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT log_id, operation, parameters, timestamp 
                   FROM replication_log 
                   WHERE applied = 0
                   ORDER BY log_id ASC
                   LIMIT ?''',
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]
            
    def mark_operations_applied(self, log_ids):
        """Mark operations as applied."""
        if not log_ids:
            return
            
        with self.get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ','.join('?' for _ in log_ids)
            cursor.execute(
                f'UPDATE replication_log SET applied = 1 WHERE log_id IN ({placeholders})',
                log_ids
            )
            conn.commit()
            
    def get_last_applied_operation_id(self):
        """Get the ID of the last applied operation."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT MAX(log_id) as last_id FROM replication_log WHERE applied = 1'
            )
            result = cursor.fetchone()
            return result['last_id'] if result and result['last_id'] is not None else 0
            
    def set_system_state(self, key, value):
        """Set a system state value."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO system_state (key, value, updated_at) 
                   VALUES (?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = excluded.updated_at''',
                (key, value, timestamp)
            )
            conn.commit()
            
    def get_system_state(self, key, default=None):
        """Get a system state value."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT value FROM system_state WHERE key = ?',
                (key,)
            )
            result = cursor.fetchone()
            return result['value'] if result else default
    
    def get_unread_messages_no_mark(self, username, count):
        """Retrieve unread messages without marking them as read."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''SELECT id, sender, content, timestamp 
                FROM messages 
                WHERE recipient = ? AND read = 0
                ORDER BY timestamp ASC
                LIMIT ?''',
                (username, count)
            )
            messages = [dict(row) for row in cursor.fetchall()]
            return messages

    def mark_messages_as_read(self, message_ids):
        """Mark the messages with the given IDs as read."""
        if not message_ids:
            return
        with self.get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ','.join('?' for _ in message_ids)
            cursor.execute(
                f'UPDATE messages SET read = 1 WHERE id IN ({placeholders})',
                message_ids
            )
            conn.commit()

    def force_delete_user(self, username):
        """Force delete a user and all their messages without checking unread status."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM messages WHERE sender = ? OR recipient = ?', (username, username))
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            conn.commit()
