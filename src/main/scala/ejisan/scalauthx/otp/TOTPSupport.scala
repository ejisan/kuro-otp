package ejisan.kuro.otp

/**
 * A Time-Based One-Time Password Algorithm (TOTP) Implementation.
 *
 * This trait is an extension of [[HOTPSupport]] and provides generation and validation of
 * the TOTP code functionality using the algorithm specified in RFC 6238 and provides
 * to an application.
 *
 * To extend this trait check the source code as reference.
 * @example
 * === Scala ===
 * {{{
 *  class TOTPAuthenticator(algorithm: OTPAlgorithm, digits: Int, otpkey: OTPKey, period: Int)
 *    extends TOTPSupport {
 *    // Generates code
 *    def generate(counter: Long): String = {
 *      intToDigits(generateForTime(
 *        algorithm,
 *        digits,
 *        period,
 *        0l,
 *        otpkey,
 *        System.currentTimeMillis() / 1000),
 *      digits)
 *    }
 *    // Validates code
 *    def validate(code: String, counter: Long): Boolean = {
 *      validateWithTime(
 *        algorithm,
 *        digits,
 *        period,
 *        0l,
 *        otpkey,
 *        System.currentTimeMillis() / 1000,
 *        digitsToInt(code))
 *    }
 *  }
 * }}}
 * === Java ===
 * {{{
 *  public class TOTPAuthenticator implements TOTPSupport {
 *    private OTPAlgorithm algorithm;
 *    private int digits;
 *    private OTPKey otpkey;
 *    private int period;
 *    TOTPAuthenticator(OTPAlgorithm algorithm, int digits, OTPKey otpkey, int period) {
 *      this.algorithm = algorithm;
 *      this.digits = digits;
 *      this.otpkey = otpkey;
 *      this.period = period;
 *    }
 *    // Generates code
 *    String generate(long counter) {
 *      return intToDigits(generateForTime(
 *        algorithm,
 *        digits,
 *        period,
 *        0l,
 *        otpkey,
 *        System.currentTimeMillis() / 1000),
 *      digits);
 *    }
 *    // Validates code
 *    boolean validate(String code, long counter) {
 *      return validateWithTime(
 *        algorithm,
 *        digits,
 *        period,
 *        0l,
 *        otpkey,
 *        System.currentTimeMillis() / 1000,
 *        digitsToInt(code));
 *    }
 *  }
 * }}}
 *
 * @see [[https://tools.ietf.org/html/rfc6238 RFC 6238]]
 */
trait TOTPSupport extends HOTPSupport {
  /**
   * The OTP protocol
   * It always returns `totp`.
   * @see [[https://tools.ietf.org/html/rfc6238 RFC 6238]]
   */
  override def protocol: String = "totp"

  /**
   * Generates HOTP codes for the given set of parameters.
   *
   * @note This method is overridden. It generates codes for both side of window to look around.
   *
   * @param window the number of window to look around.
   */
  protected override def generateForCounter(
      algorithm: OTPAlgorithm,
      digits: Int,
      otpkey: OTPKey,
      counter: Long,
      window: Int): Map[Long, Int] = {
    ((counter - window) to (counter + window))
      .map(c => c -> generateForCounter(algorithm, digits, otpkey, c))
      .toMap
  }

  /**
   * Calculates a HOTP counter.
   *
   * @param period the number of time steps.
   * @param instantTimestamp the instant Unix time.
   * @param initialTimestamp the initial Unix time.
   * @param A HOTP counter.
   */
  final def calculateCounter(
      period: Int,
      instantTimestamp: Long,
      initialTimestamp: Long = 0): Long =
    (instantTimestamp - initialTimestamp) / period

  /**
   * Generates a TOTP code for the given set of parameters.
   * This method delegates the HOTP calculation to `HOTPSupport.generateForCounter`.
   *
   * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param period the number of time steps.
   * @param initialTimestamp the initial counter Unix time.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param instantTimestamp the instant Unix time.
   * @return A TOTP code.
   */
  protected def generateForTime(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      initialTimestamp: Long,
      otpkey: OTPKey,
      instantTimestamp: Long): Int = {
    generateForCounter(
      algorithm,
      digits,
      otpkey,
      calculateCounter(period, instantTimestamp, initialTimestamp))
  }

  /**
   * Generates TOTP codes for the given set of parameters.
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param period the number of time steps.
   * @param initialTimestamp the initial counter Unix time.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param instantTimestamp the instant Unix time.
   * @param window the number of window to look around.
   * @return A `Map[Long, Int]` object that contains counter as a key and TOTP code as a value.
   */
  protected def generateForTime(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      initialTimestamp: Long,
      otpkey: OTPKey,
      instantTimestamp: Long,
      window: Int): Map[Long, Int] = {
    generateForCounter(
      algorithm,
      digits,
      otpkey,
      calculateCounter(period, instantTimestamp, initialTimestamp),
      window)
  }

  /**
   * Validates the given TOTP code for the given set of parameters.
   *
   * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
   * @see [[https://tools.ietf.org/html/rfc6238#section-5.2 Validation and Time-Step Size]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param period the number of time steps.
   * @param initialTimestamp the initial counter Unix time.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param instantTimestamp the instant Unix time.
   * @param code the TOTP code.
   * @return `true` if it's valid, `false` otherwise.
   */
  protected def validateWithTime(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      initialTimestamp: Long,
      otpkey: OTPKey,
      instantTimestamp: Long,
      code: Int): Boolean = {
    validateWithCounter(
      algorithm,
      digits,
      otpkey,
      calculateCounter(period, instantTimestamp, initialTimestamp),
      code)
  }

  /**
   * Validates the given TOTP code for the given set of parameters.
   *
   * @see [[https://tools.ietf.org/html/rfc6238#section-5.2 Validation and Time-Step Size]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param period the number of time steps.
   * @param initialTimestamp the initial counter Unix time.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   * @param instantTimestamp the instant Unix time.
   * @param window the number of window to look around.
   * @param code the TOTP code.
   * @return `Some(gap)` as the gap if the code is valid, `None` otherwise.
   */
  protected def validateWithTime(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      initialTimestamp: Long,
      otpkey: OTPKey,
      instantTimestamp: Long,
      window: Int,
      code: Int): Option[Long] = {
    validateWithCounter(
      algorithm,
      digits,
      otpkey,
      calculateCounter(period, instantTimestamp, initialTimestamp),
      window,
      code)
  }
}
