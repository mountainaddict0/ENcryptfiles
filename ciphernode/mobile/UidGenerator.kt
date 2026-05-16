package ciphernode.mobile

import java.security.SecureRandom

/**
 * Generates a cryptographic numeric UID (e.g., 1234-5678-9012).
 */
object UidGenerator {
    fun generateUid(): String {
        val digits = IntArray(12)
        val random = SecureRandom()
        for (i in digits.indices) {
            digits[i] = random.nextInt(10)
        }
        return "%d%d%d%d-%d%d%d%d-%d%d%d%d".format(
            digits[0],
            digits[1],
            digits[2],
            digits[3],
            digits[4],
            digits[5],
            digits[6],
            digits[7],
            digits[8],
            digits[9],
            digits[10],
            digits[11],
        )
    }
}
