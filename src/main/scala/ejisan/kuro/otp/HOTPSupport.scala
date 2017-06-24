package ejisan.kuro.otp

/**
 * An HMAC-Based One-Time Password Algorithm (HOTP) Implementation.
 *
 * This trait provides generation and validation of the HOTP code functionality
 * using the algorithm specified in RFC 4226 to an application.
 *
 * To extend this trait check the source code as reference.
 *
 * @example
 * === Scala ===
 * {{{
 *  class HOTPAuthenticator(algorithm: OTPAlgorithm, digits: Int, otpkey: OTPKey)
 *    extends HOTPSupport {
 *    // Generates code
 *    def generate(counter: Long): String =
 *      intToDigits(generateForCounter(algorithm, digits, otpkey, counter), digits)
 *    // Validates code
 *    def validate(code: String, counter: Long): Boolean =
 *      validateWithCounter(algorithm, digits, otpkey, counter, digitsToInt(code))
 *  }
 * }}}
 * === Java ===
 * {{{
 *  public class HOTPAuthenticator implements HOTPSupport {
 *    private OTPAlgorithm algorithm;
 *    private int digits;
 *    private OTPKey otpkey;
 *    HOTPAuthenticator(OTPAlgorithm algorithm, int digits, OTPKey otpkey) {
 *      this.algorithm = algorithm;
 *      this.digits = digits;
 *      this.otpkey = otpkey;
 *    }
 *    // Generates code
 *    String generate(long counter) {
 *      return intToDigits(generateForCounter(algorithm, digits, otpkey, counter), digits);
 *    }
 *    // Validates code
 *    boolean validate(String code, long counter) {
 *      return validateWithCounter(algorithm, digits, otpkey, counter, digitsToInt(code));
 *    }
 *  }
 * }}}
 *
 * @see [[https://tools.ietf.org/html/rfc4226 RFC 4226]]
 */
trait HOTPSupport {
  /**
   * The OTP protocol.
   * It always returns `hotp`.
   * @see [[https://tools.ietf.org/html/rfc4226 RFC 4226]]
   */
  def protocol: String = "hotp"

  /**
   * Truncates the HMAC code value to extract an HOTP value.
   */
  protected def truncate(hmac: Array[Byte], digits: Int): Int = {
    val offset = hmac(hmac.length - 1) & 0x0f
    val truncatedHash: Long =
      ((hmac(offset) & 0x7f) << 24) |
      ((hmac(offset + 1) & 0xff) << 16) |
      ((hmac(offset + 2) & 0xff) << 8) |
      (hmac(offset + 3) & 0xff).toLong
    (truncatedHash % scala.math.pow(10, digits.toDouble)).toInt
  }

  /**
   * Calculates a HMAC value.
   * This method uses the SunJCE provider to provide the HMAC algorithm.
   *
   * @see [[https://tools.ietf.org/html/rfc4226#section-5.3 Generating an HOTP Value]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param input the message to hash.
   * @return A HMAC value.
   */
  protected def hmac(algorithm: OTPAlgorithm, otpkey: OTPKey, input: Array[Byte]): Array[Byte] = {
    val mac = javax.crypto.Mac.getInstance(algorithm.value, "SunJCE")
    mac.init(otpkey.get)
    mac.doFinal(input)
  }

  /**
   * Converts the integer code to a numeric String code in base 10.
   *
   * @param code the integer code
   * @param digits the number of digits to return.
   */
  final def intToDigits(code: Int, digits: Int): String = {
    val s = code.toString
    "0" * (digits - s.length) + s
  }

  /**
   * Converts the numeric String code in base 10 to an integer code.
   *
   * @param code the integer code
   */
  final def digitsToInt(code: String): Int = {
    try {
      code.toInt
    } catch {
      case _: NumberFormatException =>
        throw new IllegalArgumentException("Invalid code digits given.")
    }
  }

  /**
   * Generates a HOTP code for the given set of parameters.
   *
   * @see [[https://tools.ietf.org/html/rfc4226#section-5.3 Generating an HOTP Value]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param counter the moving factor.
   * @return A HOTP code.
   */
  protected def generateForCounter(
      algorithm: OTPAlgorithm,
      digits: Int,
      otpkey: OTPKey,
      counter: Long): Int = {
    val buffer = java.nio.ByteBuffer.allocate(8)
    buffer.putLong(0, counter)
    truncate(hmac(algorithm, otpkey, buffer.array), digits)
  }

  /**
   * Generates HOTP codes for the given set of parameters.
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param counter the moving factor.
   * @param lookAheadWindow the number of window to look ahead.
   * @return A `Map[Long, Int]` object that contains counter as a key and a HOTP code as a value.
   */
  protected def generateForCounter(
      algorithm: OTPAlgorithm,
      digits: Int,
      otpkey: OTPKey,
      counter: Long,
      lookAheadWindow: Int): Map[Long, Int] = {
    (counter to (counter + lookAheadWindow))
      .map(c => c -> generateForCounter(algorithm, digits, otpkey, c))
      .toMap
  }

  /**
   * Validates the given HOTP code for the given set of parameters.
   *
   * @see [[https://tools.ietf.org/html/rfc4226#section-7.2 Validation of HOTP Values]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param counter the moving factor.
   * @param code the HOTP code.
   * @return `true` if it's valid, `false` otherwise.
   */
  protected def validateWithCounter(
      algorithm: OTPAlgorithm,
      digits: Int,
      otpkey: OTPKey,
      counter: Long,
      code: Int): Boolean =
    generateForCounter(algorithm, digits, otpkey, counter) == code

  /**
   * Validates the given HOTP code for the given set of parameters.
   *
   * @see `validateWithCounter`
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param counter the moving factor.
   * @param code the HOTP
   * @param lookAheadWindow the number of window to look ahead.
   * @return `Some(gap)` as the gap if the code is valid, `None` otherwise.
   */
  protected def validateWithCounter(
      algorithm: OTPAlgorithm,
      digits: Int,
      otpkey: OTPKey,
      counter: Long,
      lookAheadWindow: Int,
      code: Int): Option[Long] = {
    generateForCounter(algorithm, digits, otpkey, counter, lookAheadWindow)
      .find(_._2 == code)
      .map(_._1 - counter)
  }
}
