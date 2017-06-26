package ejisan.kuro.otp

import org.scalatest._

class OTPKeySpec extends FlatSpec with Matchers {

  "OTPKey#apply" should "create new key from a key [[java.security.Key]] instance." in {
    val gen = javax.crypto.KeyGenerator.getInstance("hmacSHA1")
    gen.init(128)
    val key1 = OTPKey(gen.generateKey)
    val key2 = OTPKey.apply(new javax.crypto.spec.SecretKeySpec(key1.toByteArray, "RAW"))
    key1 should be (key2)
  }

  it should "validate key length of at least 128 bits with the parameter [strict = true]" in {
    val gen = javax.crypto.KeyGenerator.getInstance("hmacSHA1")
    gen.init(120)
    a [IllegalArgumentException] should be thrownBy {
      OTPKey(gen.generateKey, true)
    }
  }

  it should "validate key length of at least 128 bits with the parameter [strict = false]" in {
    val gen = javax.crypto.KeyGenerator.getInstance("hmacSHA1")
    gen.init(72)
    a [IllegalArgumentException] should be thrownBy {
      OTPKey(gen.generateKey, false)
    }
  }

  "OTPKey#fromByteArray" should "create new key from byte array [OTPKey.toByteArray]." in {
    val key = OTPKey.random(OTPAlgorithm.SHA1)
    OTPKey.fromByteArray(key.toByteArray) should be (key)
  }

  "OTPKey#fromHex" should "create new key from hex decimal [OTPKey.toHex]." in {
    val key = OTPKey.random(OTPAlgorithm.SHA1)
    OTPKey.fromHex(key.toHex) should be (key)
  }

  "OTPKey#fromBase64" should "create new key from Base64 [OTPKey.toBase64] or [OTPKey.toBase64WithoutPadding]" in {
    val key = OTPKey.random(OTPAlgorithm.SHA1)
    OTPKey.fromBase64(key.toBase64) should be (key)
    OTPKey.fromBase64(key.toBase64WithoutPadding) should be (key)
  }

  "OTPKey#fromBase64URL" should "create new key from Base64 URL-Safe [OTPKey.toBase64URL] or [OTPKey.toBase64URLWithoutPadding]" in {
    val key = OTPKey.random(OTPAlgorithm.SHA1)
    OTPKey.fromBase64URL(key.toBase64URL) should be (key)
    OTPKey.fromBase64URL(key.toBase64URLWithoutPadding) should be (key)
  }

  "OTPKey#fromBase32" should "create new key from Base32 from [OTPKey.toBase32] or [OTPKey.toBase32WithoutPadding]" in {
    val key = OTPKey.random(OTPAlgorithm.SHA1)
    OTPKey.fromBase32(key.toBase32) should be (key)
    OTPKey.fromBase32(key.toBase32WithoutPadding) should be (key)
  }

  "OTPKey#fromBase32Hex" should "create new key from Base32 Hex from [OTPKey.toBase32Hex] or [OTPKey.toBase32HexWithoutPadding]" in {
    val key = OTPKey.random(OTPAlgorithm.SHA1)
    OTPKey.fromBase32Hex(key.toBase32Hex) should be (key)
    OTPKey.fromBase32Hex(key.toBase32HexWithoutPadding) should be (key)
  }

  "OTPKey#random" should "generate key length of default length" in {
    val md5Key = OTPKey.random(OTPAlgorithm.MD5)
    md5Key.keyLength should be (OTPAlgorithm.MD5.defaultKeyLength)
    val sha1Key = OTPKey.random(OTPAlgorithm.SHA1)
    sha1Key.keyLength should be (OTPAlgorithm.SHA1.defaultKeyLength)
    val sha256Key = OTPKey.random(OTPAlgorithm.SHA256)
    sha256Key.keyLength should be (OTPAlgorithm.SHA256.defaultKeyLength)
    val sha512Key = OTPKey.random(OTPAlgorithm.SHA512)
    sha512Key.keyLength should be (OTPAlgorithm.SHA512.defaultKeyLength)
  }

  "OTPKey#randomStrong" should "generate key length of default strong length" in {
    val md5Key = OTPKey.randomStrong(OTPAlgorithm.MD5)
    md5Key.keyLength should be (OTPAlgorithm.MD5.strongKeyLength)
    val sha1Key = OTPKey.randomStrong(OTPAlgorithm.SHA1)
    sha1Key.keyLength should be (OTPAlgorithm.SHA1.strongKeyLength)
    val sha256Key = OTPKey.randomStrong(OTPAlgorithm.SHA256)
    sha256Key.keyLength should be (OTPAlgorithm.SHA256.strongKeyLength)
    val sha512Key = OTPKey.randomStrong(OTPAlgorithm.SHA512)
    sha512Key.keyLength should be (OTPAlgorithm.SHA512.strongKeyLength)
  }
}
