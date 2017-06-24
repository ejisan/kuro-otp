package ejisan.kuro.otp

import java.net.URI
import scala.collection.JavaConverters._
import scala.compat.java8.OptionConverters._

/**
 * A TOTP Authenticator Implementation.
 *
 * @see [[https://tools.ietf.org/html/rfc6238 RFC 6238]]
 * @see [[TOTP$ TOTP Factory]]
 *
 * @param algorithm the hash function used to calculate the HMAC.
 * @param digits the number of digits to truncate.
 * @param period the number of time steps.
 * @param initialTimestamp the initial counter Unix time.
 * @param otpkey the shared secret key as [[OTPKey]] instance.
 */
class TOTP(
    val algorithm: OTPAlgorithm,
    val digits: Int,
    val period: Int,
    val initialTimestamp: Long,
    val otpkey: OTPKey) extends TOTPSupport {

  /**
   * Returns current time that this generator uses.
   */
  def currentTime(): Long =
    System.currentTimeMillis() / 1000

  /**
   * Generates a TOTP code for the current time.
   *
   * @see [[currentTime currentTime()]]
   * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
   *
   * @return A numeric String TOTP code in base 10.
   */
  def generate(): String = generate(currentTime())

  /**
   * Generates a TOTP code for the given instant of time.
   *
   * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
   *
   * @param instantTimestamp the instant of time.
   * @return A numeric String TOTP code in base 10.
   */
  def generate(instantTimestamp: Long): String = {
    intToDigits(generateForTime(
        algorithm,
        digits,
        period,
        initialTimestamp,
        otpkey,
        instantTimestamp),
      digits)
  }

  /**
   * Generates TOTP codes for the given instant of time.
   *
   * @param window the number of window to look around.
   * @return A `Map[Long, String]` object that contains counter as a key
   *         and a numeric String TOTP code in base 10 as a value.
   */
  def generate(instantTimestamp: Long, window: Int): Map[Long, String] = {
    generateForTime(
        algorithm,
        digits,
        period,
        initialTimestamp,
        otpkey,
        instantTimestamp,
        window)
      .mapValues(intToDigits(_, digits))
  }

  /**
   * Java API: Generates TOTP codes for the given instant of time.
   *
   * @see [[TOTP.generate(instantTimestamp:Long,window:Int):Map[Long,String]* TOTP.generate]]
   */
  def generateAsJava(instantTimestamp: Long, window: Int): java.util.Map[java.lang.Long, String] = {
    generate(instantTimestamp, window)
      .map({ case (k, v) => (Long.box(k), v) })
      .asJava
  }

  /**
   * Validates the given TOTP code for current time.
   *
   * @see [[currentTime currentTime()]]
   * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
   * @see [[https://tools.ietf.org/html/rfc6238#section-5.2 Validation and Time-Step Size]]
   *
   * @param code the numeric String TOTP code in base 10.
   * @return `true` if it's valid, `false` otherwise.
   */
  def validate(code: String): Boolean = validate(currentTime(), code)

  /**
   * Validates the given TOTP code for the given instant of time.
   *
   * @see [[currentTime currentTime()]]
   * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
   * @see [[https://tools.ietf.org/html/rfc6238#section-5.2 Validation and Time-Step Size]]
   *
   * @param instantTimestamp the instant of time.
   * @return `true` if it's valid, `false` otherwise.
   */
  def validate(instantTimestamp: Long, code: String): Boolean = {
    validateWithTime(
      algorithm,
      digits,
      period,
      initialTimestamp,
      otpkey,
      instantTimestamp,
      digitsToInt(code))
  }

  /**
   * Validates the given TOTP code for current time.
   *
   * @see [[currentTime currentTime()]]
   *
   * @param window the number of window to look around.
   * @return `Some(gap)` as valid counter and the gap if it's valid, `None` otherwise.
   */
  def validate(window: Int, code: String): Option[Long] = validate(currentTime(), window, code)

  /**
   * Validates the given TOTP code for the instant of time.
   *
   * @param instantTimestamp the instant of time.
   * @param window the number of window to look around.
   * @param code the numeric String TOTP code in base 10.
   * @return `Some(gap)` as valid counter and the gap if it's valid, `None` otherwise.
   */
  def validate(instantTimestamp: Long, window: Int, code: String): Option[Long] = {
    validateWithTime(
      algorithm,
      digits,
      period,
      initialTimestamp,
      otpkey,
      instantTimestamp,
      window,
      digitsToInt(code))
  }

  /**
   * Java API: Validates the given TOTP code for the instant of time.
   *
   * @see [[TOTP.validate(window:Int,code:String):java.util.OptionalLong* TOTP.validate]]
   */
  def validateAsJava(window: Int, code: String): java.util.OptionalLong =
    validateAsJava(currentTime(), window, code)

  /**
   * Java API: Validates the given TOTP code for the instant of time.
   *
   * @see [[TOTP.validate(instantTimestamp:Long,window:Int,code:String):java.util.OptionalLong* TOTP.validate]]
   */
  def validateAsJava(instantTimestamp: Long, window: Int, code: String): java.util.OptionalLong =
    validate(instantTimestamp, window, code).asPrimitive

  /**
   * Returns a URI instance with TOTP configurations.
   *
   * @see [[https://github.com/google/google-authenticator/wiki/Key-Uri-Format Key URI Format]]
   *
   * @param account the account name of the subject.
   * @param issuer the service provider name.
   * @param params the additional parameters.
   */
  def toURI(
      account: String,
      issuer: Option[String] = None,
      params: Map[String, String] = Map()): URI = {
    val p = Map(
      "digits" -> digits.toString,
      "period" -> period.toString,
      "algorithm" -> algorithm.name)
    OTPAuthURICodec.encode(
      protocol,
      account,
      otpkey,
      issuer,
      params ++ p)
  }

  /**
   * Java API: Returns a URI instance with TOTP configurations.
   */
  def toURI(
      account: String,
      issuer: java.util.Optional[String],
      params: java.util.Map[String, String]): URI =
    toURI(account, issuer.asScala, params.asScala.toMap)

  override def toString: String =
    s"TOTP(${otpkey.toBase32}, ${algorithm.name}, $digits, $period, $initialTimestamp)"

  override def hashCode() = {
    41 * (
      41 * (
        41 * (
          41 * otpkey.hashCode + algorithm.hashCode) +
        digits.hashCode) +
      period.hashCode) +
    initialTimestamp.hashCode
  }

  override def equals(obj: Any): Boolean = obj match {
    case o: TOTP =>
      o.otpkey == otpkey &&
      o.algorithm == algorithm &&
      o.digits == digits &&
      o.period == period &&
      o.initialTimestamp == initialTimestamp
    case _ => false
  }
}

/**
 * Factory for [[TOTP]] instances.
 *
 * @see [[https://tools.ietf.org/html/rfc6238 RFC 6238]]
 *
 * @example
 * === Scala ===
 * {{{
 *  val totp = TOTP(OTPAlgorithm.SHA1, 6, 30, OTPKey.random(OTPAlgorithm.SHA1))
 *  val code1 = totp.generate()
 *  if (totp.validate(code1)) {
 *    println("You are authenticated!")
 *  }
 *  val code2 = totp.generate(3l)
 *  totp.validate(5, code2) foreach { gap =>
 *    println(s"You are authenticated! (gap: $gap)")
 *  }
 * }}}
 * === Java ===
 * {{{
 *  TOTP totp = TOTP.getInstance(OTPAlgorithm.getSHA1(), 6, 30, OTPKey.random(OTPAlgorithm.getSHA1()));
 *  String code1 = totp.generate();
 *  if (totp.validate(code1)) {
 *    System.out.println("You are authenticated!");
 *  }
 *  String code2 = totp.generate(3l);
 *  java.util.OptionalLong result = totp.validateAsJava(5, code2);
 *  if (result.isPresent()) {
 *    System.out.println("You are authenticated! (gap: " + result.getAsLong() + ")");
 *  }
 * }}}
 */
object TOTP {
  /**
   * Creates new [[TOTP]] instance.
   *
   * @see [[https://tools.ietf.org/html/rfc6238 RFC 6238]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param period the number of time steps.
   * @param initialTimestamp the initial counter Unix time.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   */
  def apply(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      initialTimestamp: Long,
      otpkey: OTPKey): TOTP = {
    new TOTP(algorithm, digits, period, initialTimestamp, otpkey)
  }

  /**
   * Creates new [[TOTP]] instance.
   *
   * @see [[https://tools.ietf.org/html/rfc6238 RFC 6238]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param period the number of time steps.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   */
  def apply(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      otpkey: OTPKey): TOTP =
    apply(algorithm, digits, period, 0l, otpkey)

  /**
   * Java API: Creates new [[TOTP]] instance.
   */
  def getInstance(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      initialTimestamp: Long,
      otpkey: OTPKey): TOTP =
    apply(algorithm, digits, period, initialTimestamp, otpkey)

  /**
   * Java API: Creates new [[TOTP]] instance.
   */
  def getInstance(
      algorithm: OTPAlgorithm,
      digits: Int,
      period: Int,
      otpkey: OTPKey): TOTP =
    apply(algorithm, digits, period, 0l, otpkey)

  /**
   * Creates new [[TOTP]] instance from `otpauth` URI.
   *
   * @see [[https://github.com/google/google-authenticator/wiki/Key-Uri-Format Key URI Format]]
   */
  def fromURI(uri: URI): TOTP = {
    import scala.util.control.Exception.allCatch
    OTPAuthURICodec.decode(uri) match {
      case Some(decoded) =>
        apply(
          decoded.params.get("algorithm").flatMap(OTPAlgorithm.find).getOrElse(OTPAlgorithm.SHA1),
          decoded.params.get("digits").flatMap(d => allCatch.opt(d.toInt)).getOrElse(6),
          decoded.params.get("period").flatMap(d => allCatch.opt(d.toInt)).getOrElse(6),
          decoded.otpkey)
      case None => throw new IllegalArgumentException("Illegal URI given.")
    }
  }
}
