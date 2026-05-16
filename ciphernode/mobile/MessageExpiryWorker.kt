package ciphernode.mobile

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Background worker that purges read messages once TTL expires.
 * UI layers should observe message tables and reactively drop expired rows.
 */
class MessageExpiryWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val helper = CipherNodeDatabase(applicationContext)
        val pool = CipherNodeDbPool(helper)
        val now = System.currentTimeMillis()

        pool.withConnection { db ->
            db.compileStatement(
                """
                DELETE FROM messages
                WHERE read_status = 1
                  AND expiry_timestamp IS NOT NULL
                  AND expiry_timestamp <= ?
                """.trimIndent(),
            ).use { statement ->
                statement.bindLong(1, now)
                statement.executeUpdateDelete()
            }
        }
        Result.success()
    }
}
