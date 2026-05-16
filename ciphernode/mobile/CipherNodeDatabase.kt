package ciphernode.mobile

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.util.concurrent.Semaphore

/**
 * SQLiteOpenHelper with secure defaults, foreign-key enforcement, and migrations.
 */
class CipherNodeDatabase(context: Context) : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
        db.execSQL("PRAGMA journal_mode=WAL;")
        db.execSQL("PRAGMA synchronous=NORMAL;")
        db.execSQL("PRAGMA busy_timeout=5000;")
    }

    override fun onCreate(db: SQLiteDatabase) {
        migrate(db, 0, DB_VERSION)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        migrate(db, oldVersion, newVersion)
    }

    private fun migrate(db: SQLiteDatabase, fromVersion: Int, toVersion: Int) {
        db.beginTransaction()
        try {
            for (version in (fromVersion + 1)..toVersion) {
                when (version) {
                    1 -> applyV1(db)
                }
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    private fun applyV1(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS users (
                uid TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER
            );
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL CHECK (status IN ('active', 'archived', 'blocked')),
                ephemeral_toggle INTEGER NOT NULL DEFAULT 0,
                ttl_setting INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER
            );
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_id TEXT NOT NULL,
                payload_encrypted BLOB NOT NULL,
                file_blob_pointer TEXT,
                timestamp INTEGER NOT NULL,
                read_status INTEGER NOT NULL DEFAULT 0,
                expiry_timestamp INTEGER,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(uid) ON DELETE CASCADE
            );
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_conversation
            ON messages(conversation_id, timestamp);
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_expiry
            ON messages(read_status, expiry_timestamp);
            """.trimIndent(),
        )
    }

    companion object {
        private const val DB_NAME = "ciphernode.db"
        private const val DB_VERSION = 1
    }
}

/**
 * Simple concurrency guard to avoid unbounded parallel writes against SQLite.
 */
class CipherNodeDbPool(private val helper: CipherNodeDatabase, poolSize: Int = 2) {
    private val semaphore = Semaphore(poolSize, true)

    fun <T> withConnection(block: (SQLiteDatabase) -> T): T {
        semaphore.acquire()
        return try {
            block(helper.writableDatabase)
        } finally {
            semaphore.release()
        }
    }
}
