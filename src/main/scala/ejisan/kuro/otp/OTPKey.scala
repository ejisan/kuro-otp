package ejisan.kuro.otp

import java.util.{ Arrays, Base64 }
import java.security.{ Key, SecureRandom }
import org.apache.commons.codec.binary.{ Base32, Hex }

/**
 * A representation of a HMAC-based OTP key.
 *
 * @param key the raw formated key.
 * @see <a href="https://tools.ietf.org/html/rfc4226#section-7.5">RFC4226 Section-7.5</a>
 */
class OTPKey private (key: Key) {
  /**
   * Returns the java key instance.
   */
  def get: Key = key

  /**
   * Returns key as byte array.
   */
  def toByteArray: Array[Byte] = key.getEncoded

  /**
   * Returns key as hex decimal.
   */
  def toHex: String =
    new String((new Hex).encode(toByteArray), java.nio.charset.StandardCharsets.UTF_8)

  /**
   * Returns base64 encoded key.
   */
  def toBase64: String =
    Base64.getEncoder.encodeToString(toByteArray)

  /**
   * Returns base64 without padding encoded key.
   */
  def toBase64WithoutPadding: String =
    Base64.getEncoder.withoutPadding.encodeToString(toByteArray)

  /**
   * Returns base64 URL-Safe encoded key.
   */
  def toBase64URL: String =
    Base64.getUrlEncoder.encodeToString(toByteArray)

  /**
   * Returns base64 URL-Safe without padding encoded key.
   */
  def toBase64URLWithoutPadding: String =
    Base64.getUrlEncoder.encodeToString(toByteArray)

  /**
   * Returns base32 encoded key.
   */
  def toBase32: String =
    (new Base32).encodeToString(toByteArray)

  /**
   * Returns base32 without padding encoded key.
   */
  def toBase32WithoutPadding: String =
    (new Base32).encodeToString(toByteArray).replace("=", "")

  /**
   * Returns base32 HEX encoded key.
   */
  def toBase32Hex: String =
    (new Base32(true)).encodeToString(toByteArray)

  /**
   * Returns base32 HEX without padding encoded key.
   */
  def toBase32HexWithoutPadding: String =
    (new Base32(true)).encodeToString(toByteArray).replace("=", "")

  /**
   * The size of the length of this key byte.
   */
  def byteLength: Int = toByteArray.length

  /**
   * The size of the length of this key.
   */
  def keyLength: Int = toByteArray.length * 8

  override def toString: String = s"OTPKey($toBase32)"

  override def hashCode: Int = Arrays.hashCode(toByteArray)

  override def equals(obj: Any): Boolean = obj match {
    case key: OTPKey => Arrays.equals(key.toByteArray, toByteArray)
    case _ => false
  }
}

/**
 * Factory for [[OTPKey]] instances.
 *
 * There are several possibilities for creating keys:
 * @example {{{
 *  // Random key generation
 *  // Scala
 *  OTPKey.randomStrong(OTPAlgorithm.SHA1) // It generates the key with length strong enough
 *  OTPKey.random(OTPAlgorithm.SHA1)
 *  // Java
 *  OTPKey.randomStrong(OTPAlgorithm.getSHA1()); // It generates the key with length strong enough
 *  OTPKey.random(OTPAlgorithm.getSHA1());
 *
 *  // Create from [[java.security.Key]]
 *  // Scala
 *  OTPKey(new SecretKeySpec(bytes, "RAW")) // same as OTPKey.fromByteArray(bytes)
 *  OTPKey(new SecretKeySpec(bytes, "RAW"), false) // same as OTPKey.fromByteArray(bytes)
 *  // Java
 *  OTPKey.getInstance(new SecretKeySpec(bytes, "RAW")); // same as OTPKey.fromByteArray(bytes)
 *  OTPKey.getInstance(new SecretKeySpec(bytes, "RAW"), false); // same as OTPKey.fromByteArray(bytes)
 *
 *  // Create from serialized key
 *  // Scala or Java
 *  OTPKey.fromByteArray(bytes)
 *  OTPKey.fromBase64("d6/LRKo1lAOdjpX8+eyc/pqisPE=")
 *  OTPKey.fromBase64URL("d6_LRKo1lAOdjpX8-eyc_pqisPE=")
 *  OTPKey.fromBase32("O6X4WRFKGWKAHHMOSX6PT3E472NKFMHR")
 *  OTPKey.fromBase32Hex("EUNSMH5A6MA077CEINUFJR4SVQDA5C7H")
 * }}}
 */
object OTPKey {
  /**
   * Creates new [[OTPKey]] instance.
   *
   * @param key the RAW format key
   * @param strict if true then enable strict key length validation as RFC 4226 requires,
   *               if false then disable strict key length validation that allows short key length as 80 bits.
   * @see https://tools.ietf.org/html/rfc4226#section-4
   */
  def apply(key: Key, strict: Boolean = true): OTPKey = {
    if (strict) {
      require(
        key.getEncoded.length >= 16,
        "RFC 4226 requires key length of at least 128 bits and recommends key length of 160 bits. If you need to use lower key length disable strict mode.")
    } else {
      require(
        key.getEncoded.length >= 10,
        "Key length must be at least 80 bits. RFC 4226 requires key length of at least 128 bits and recommends key length of 160 bits.")
    }
    require(key.getFormat.toUpperCase == "RAW", "Invalid Key format. It must be \"RAW\".")
    new OTPKey(key)
  }

  def unapply(otpkey: OTPKey): Option[Key] = Some(otpkey.get)

  /**
   * JAVA API: Creates new [[OTPKey]] instance.
   *
   * @param key the RAW format key
   * @param strict if true then enable strict key length validation as RFC 4226 requires,
   *               if false then disable strict key length validation that allows short key length as 80 bits.
   * @see https://tools.ietf.org/html/rfc4226#section-4
   */
  def getInstance(key: Key, strict: Boolean): OTPKey = apply(key, strict)

  /**
   * Creates new [[OTPKey]] instance without key length validation.
   *
   * @param key the RAW format key
   */
  @deprecated("Use apply method with key length validation. Key length must be at least 80 bits. RFC 4226 requires key length of at least 128 bits and recommends key length of 160 bits.", "0.0.1")
  def lenient(key: Key): OTPKey = {
    require(key.getFormat.toUpperCase == "RAW", "Invalid Key format. It must be \"RAW\".")
    new OTPKey(key)
  }

  /**
   * Creates new [[OTPKey]] instance from byte array.
   */
  def fromByteArray(bytes: Array[Byte], strict: Boolean = true): OTPKey =
    apply(new javax.crypto.spec.SecretKeySpec(bytes, "RAW"), strict)

  /**
   * Creates new [[OTPKey]] instance from hex decimal.
   */
  def fromHex(hexDecimal: String, strict: Boolean = true): OTPKey =
    fromByteArray((new Hex).decode(hexDecimal.getBytes), strict)

  /**
   * Creates new [[OTPKey]] instance from base64 or base64 without padding encoded key.
   */
  def fromBase64(base64: String, strict: Boolean = true): OTPKey =
    fromByteArray(Base64.getDecoder.decode(base64), strict)

  /**
   * Creates new [[OTPKey]] instance from base64 URL-Safe or base64 URL-Safe without padding encoded key.
   */
  def fromBase64URL(base64Url: String, strict: Boolean = true): OTPKey =
    fromByteArray(Base64.getUrlDecoder.decode(base64Url), strict)

  /**
   * Creates new [[OTPKey]] instance from base32 or base32 without padding encoded key.
   */
  def fromBase32(base32: String, strict: Boolean = true): OTPKey =
    fromByteArray((new Base32).decode(base32), strict)

  /**
   * Creates new [[OTPKey]] instance from base32 Hex or base32 Hex without padding encoded key.
   */
  def fromBase32Hex(base32Hex: String, strict: Boolean = true): OTPKey =
    fromByteArray((new Base32(true)).decode(base32Hex), strict)

  @inline
  private def defaultPRNG: SecureRandom =
    SecureRandom.getInstance("NativePRNGNonBlocking", "SUN")

  /**
   * Generates random [[OTPKey]] instance.
   *
   * @param keyLength the key length
   * @param algorithm the algorithm
   * @param prng the random number generator
   */
  def random(keyLength: Int, algorithm: OTPAlgorithm, strict: Boolean, prng: SecureRandom): OTPKey = {
    val gen = javax.crypto.KeyGenerator.getInstance(algorithm.value)
    gen.init(keyLength, prng)
    apply(gen.generateKey, strict)
  }

  /**
   * Generates random [[OTPKey]] instance.
   *
   * @param keyLength the key length
   * @param algorithm the algorithm
   * @param strict
   */
  def random(keyLength: Int, algorithm: OTPAlgorithm, strict: Boolean = true): OTPKey =
    random(keyLength, algorithm, strict, defaultPRNG)

  /**
   * Generates random [[OTPKey]] instance with default key length.
   *
   * @param algorithm the algorithm
   * @param prng the random number generator
   */
  def random(algorithm: OTPAlgorithm, prng: SecureRandom): OTPKey =
    random(algorithm.defaultKeyLength, algorithm, false, prng)

  /**
   * Generates random [[OTPKey]] instance with default key length.
   */
  def random(algorithm: OTPAlgorithm): OTPKey =
    random(algorithm, defaultPRNG)

  /**
   * Generates random [[OTPKey]] instance with stronger key length.
   *
   * @param algorithm the algorithm
   * @param prng the random number generator
   */
  def randomStrong(algorithm: OTPAlgorithm, prng: SecureRandom): OTPKey =
    random(algorithm.strongKeyLength, algorithm, false, prng)

  /**
   * Generates random [[OTPKey]] instance with stronger key length.
   */
  def randomStrong(algorithm: OTPAlgorithm): OTPKey =
    randomStrong(algorithm, defaultPRNG)
}
