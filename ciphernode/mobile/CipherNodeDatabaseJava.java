package ciphernode.mobile;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/**
 * Java variant of the CipherNode SQLite helper with secure defaults and migrations.
 */
public final class CipherNodeDatabaseJava extends SQLiteOpenHelper {
    private static final String DB_NAME = "ciphernode.db";
    private static final int DB_VERSION = 1;

    public CipherNodeDatabaseJava(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        super.onConfigure(db);
        db.setForeignKeyConstraintsEnabled(true);
        db.execSQL("PRAGMA journal_mode=WAL;");
        db.execSQL("PRAGMA synchronous=NORMAL;");
        db.execSQL("PRAGMA busy_timeout=5000;");
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        applyV1(db);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.beginTransaction();
        try {
            for (int version = oldVersion + 1; version <= newVersion; version += 1) {
                if (version == 1) {
                    applyV1(db);
                }
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    private void applyV1(SQLiteDatabase db) {
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS users (" +
                "uid TEXT PRIMARY KEY, " +
                "public_key TEXT NOT NULL, " +
                "created_at INTEGER NOT NULL, " +
                "last_seen INTEGER" +
            ");"
        );
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS conversations (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "status TEXT NOT NULL CHECK (status IN ('active', 'archived', 'blocked')), " +
                "ephemeral_toggle INTEGER NOT NULL DEFAULT 0, " +
                "ttl_setting INTEGER NOT NULL DEFAULT 0, " +
                "created_at INTEGER NOT NULL, " +
                "updated_at INTEGER" +
            ");"
        );
        db.execSQL(
            "CREATE TABLE IF NOT EXISTS messages (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "conversation_id INTEGER NOT NULL, " +
                "sender_id TEXT NOT NULL, " +
                "payload_encrypted BLOB NOT NULL, " +
                "file_blob_pointer TEXT, " +
                "timestamp INTEGER NOT NULL, " +
                "read_status INTEGER NOT NULL DEFAULT 0, " +
                "expiry_timestamp INTEGER, " +
                "FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE, " +
                "FOREIGN KEY (sender_id) REFERENCES users(uid) ON DELETE CASCADE" +
            ");"
        );
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_messages_conversation " +
                "ON messages(conversation_id, timestamp);"
        );
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_messages_expiry " +
                "ON messages(read_status, expiry_timestamp);"
        );
    }
}
