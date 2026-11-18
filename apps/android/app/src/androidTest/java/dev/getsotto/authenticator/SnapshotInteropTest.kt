package dev.getsotto.authenticator

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SnapshotInteropTest {
    @Test
    fun decryptsSharedGoldenVector() {
        val plaintext = decryptTestSnapshot(TEST_KEY, Base64.decode(SHARED_ENVELOPE, Base64.DEFAULT))
        assertEquals(SNAPSHOT_JSON, plaintext)
    }

    @Test
    fun encryptsTheSameVectorAsSwiftBinding() {
        val envelope = encryptTestSnapshot(TEST_KEY, TEST_NONCE, SNAPSHOT_JSON)
        val envelopeBase64 = Base64.encodeToString(envelope, Base64.NO_WRAP)
        assertEquals(SHARED_ENVELOPE, envelopeBase64)
    }

    @Test
    fun rejectsModifiedCiphertextAndUnsupportedVersion() {
        val envelope = Base64.decode(SHARED_ENVELOPE, Base64.DEFAULT)
        val modifiedCiphertext = envelope.clone().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertTrue(runCatching { decryptTestSnapshot(TEST_KEY, modifiedCiphertext) }.isFailure)

        val unsupportedVersion = envelope.clone().also { it[4] = 2 }
        assertTrue(runCatching { decryptTestSnapshot(TEST_KEY, unsupportedVersion) }.isFailure)
    }

    private companion object {
        private val TEST_KEY = ByteArray(32) { 0x11 } // gitleaks:allow -- public synthetic interoperability fixture only
        private val TEST_NONCE = ByteArray(12) { 0x22 } // gitleaks:allow -- public synthetic interoperability fixture only
        private const val SNAPSHOT_JSON = "{\"formatVersion\":1,\"project\":\"synthetic-project\",\"instance\":\"synthetic-instance\",\"label\":\"Synthetic test entry\"}"
        private const val SHARED_ENVELOPE = "U09UMQEAIiIiIiIiIiIiIiIibNVhJrKi/iuzWqxPIcmH9yWi4cAa88MhNyx+yjPDFnorC8NnJ8Ga8z4qgkeDOz0Xn/D3DOYGG5DXEcjDwBiW3AzkeUw45nx7hRJC8HmKmy7Jn89fYYu3cWMjgtNQ1mmx/CgwPg0y+Dp8+YNjBiK9WDFhOaPPYO0z7/+PPTYi1dw="
    }
}
