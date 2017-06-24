package ejisan.kuro.otp

import java.net.URI
import scala.collection.JavaConverters._
import scala.compat.java8.OptionConverters._

/**
 * A HOTP Authenticator Implementation.
 *
 * @see [[https://tools.ietf.org/html/rfc4226 RFC 4226]]
 * @see [[HOTP$ HOTP Factory]]
 *
 * @param algorithm the hash function used to calculate the HMAC.
 * @param digits the number of digits to truncate.
 * @param otpkey the shared secret key as [[OTPKey]] instance.
 */
class HOTP(
    val algorithm: OTPAlgorithm,
    val digits: Int,
    val otpkey: OTPKey) extends HOTPSupport {

  /**
   * Generates a HOTP code for the given counter.
   *
   * @see [[https://tools.ietf.org/html/rfc4226#section-5.3 Generating an HOTP Value]]
   *
   * @param counter the moving factor.
   * @return A numeric String HOTP code in base 10.
   */
  def generate(counter: Long): String =
    intToDigits(generateForCounter(algorithm, digits, otpkey, counter), digits)

  /**
   * Generates HOTP codes for the given counter.
   *
   * @see [[https://tools.ietf.org/html/rfc4226#section-5.3 Generating an HOTP Value]]
   *
   * @param counter the moving factor.
   * @param lookAheadWindow the number of window to look ahead.
   * @return A `Map[Long, String]` object that contains counter as a key
   *         and a numeric String HOTP code in base 10 as a value.
   */
  def generate(counter: Long, lookAheadWindow: Int): Map[Long, String] = {
    generateForCounter(algorithm, digits, otpkey, counter, lookAheadWindow)
      .mapValues(intToDigits(_, digits))
  }

  /**
   * Java API: Generates HOTP codes for the given counter.
   *
   * @see [[HOTP.generate(counter:Long,lookAheadWindow:Int):Map[Long,String]* HOTP.generate]]
   */
  def generateAsJava(
      counter: Long,
      lookAheadWindow: Int): java.util.Map[java.lang.Long, String] = {
    generate(counter, lookAheadWindow)
      .map({ case (k, v) => (Long.box(k), v) })
      .asJava
  }

  /**
   * Validates the given HOTP code for the given counter.
   *
   * @see [[https://tools.ietf.org/html/rfc4226#section-7.2 Validation of HOTP Values]]
   *
   * @param counter the moving factor.
   * @param code the numeric String HOTP code in base 10.
   * @return `true` if it's valid, `false` otherwise.
   */
  def validate(counter: Long, code: String): Boolean =
    validateWithCounter(algorithm, digits, otpkey, counter, digitsToInt(code))

  /**
   * Validates the given HOTP code for the given counter.
   *
   * @param counter the moving factor.
   * @param lookAheadWindow the number of window to look ahead.
   * @param code the numeric String HOTP code in base 10.
   * @return `Some(gap)` as valid counter and the gap if it's valid, `None` otherwise.
   */
  def validate(counter: Long, lookAheadWindow: Int, code: String): Option[Long] =
    validateWithCounter(algorithm, digits, otpkey, counter, lookAheadWindow, digitsToInt(code))

  /**
   * Java API: Validates the given HOTP code for the given counter.
   *
   * @see [[HOTP.validate(counter:Long,lookAheadWindow:Int,code:String):Option[Long]* HOTP.validate]]
   */
  def validateAsJava(
      counter: Long,
      lookAheadWindow: Int,
      code: String): java.util.OptionalLong =
    validate(counter, lookAheadWindow, code).asPrimitive

  /**
   * Returns a URI instance with HOTP configurations.
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
    OTPAuthURICodec.encode(
      protocol,
      account,
      otpkey,
      issuer,
      params ++ Map("digits" -> digits.toString, "algorithm" -> algorithm.name))
  }

  /**
   * Java API: Returns a URI instance with HOTP configurations.
   *
   * @see [[HOTP.toURI(account:String,issuer:Option[String],params:Map[String,String]):java\.net\.URI* HOTP.toURI]]
   */
  def toURI(
      account: String,
      issuer: java.util.Optional[String],
      params: java.util.Map[String, String]): URI =
    toURI(account, issuer.asScala, params.asScala.toMap)

  override def toString: String = s"HOTP(${otpkey.toBase32}, ${algorithm.name}, $digits)"

  override def hashCode() = 41 * (41 * otpkey.hashCode + algorithm.hashCode) + digits.hashCode

  override def equals(obj: Any): Boolean = obj match {
    case o: HOTP => o.otpkey == otpkey && o.algorithm == algorithm && o.digits == digits
    case _ => false
  }
}

/**
 * Factory for [[HOTP]] instances.
 *
 * @see [[https://tools.ietf.org/html/rfc4226 RFC 4226]]
 *
 * @example
 * === Scala ===
 * {{{
 *  val hotp = HOTP(OTPAlgorithm.SHA1, 6, OTPKey.random(OTPAlgorithm.SHA1))
 *  val code1 = hotp.generate(0l)
 *  if (hotp.validate(0l, code1)) {
 *    println("You are authenticated!")
 *  }
 *  val code2 = hotp.generate(3l)
 *  hotp.validate(0l, 5, code2) foreach { gap =>
 *    println(s"You are authenticated! (gap: $gap)")
 *  }
 * }}}
 * === Java ===
 * {{{
 *  HOTP hotp = HOTP.getInstance(OTPAlgorithm.getSHA1(), 6, OTPKey.random(OTPAlgorithm.getSHA1()));
 *  String code1 = hotp.generate(0l);
 *  if (hotp.validate(0l, code1)) {
 *    System.out.println("You are authenticated!");
 *  }
 *  String code2 = hotp.generate(3l);
 *  java.util.OptionalLong result = hotp.validateAsJava(0l, 5, code2);
 *  if (result.isPresent()) {
 *    System.out.println("You are authenticated! (gap: " + result.getAsLong() + ")");
 *  }
 * }}}
 */
object HOTP {
  /**
   * Creates new [[HOTP]] instance.
   *
   * @see [[https://tools.ietf.org/html/rfc4226 RFC 4226]]
   *
   * @param algorithm the hash function used to calculate the HMAC.
   * @param digits the number of digits to truncate.
   * @param otpkey the shared secret key as [[OTPKey]] instance.
   */
  def apply(algorithm: OTPAlgorithm, digits: Int, otpkey: OTPKey): HOTP = {
    new HOTP(algorithm, digits, otpkey)
  }

  /**
   * Java API: Creates new [[HOTP]] instance.
   */
  def getInstance(algorithm: OTPAlgorithm, digits: Int, otpkey: OTPKey): HOTP =
    apply(algorithm, digits, otpkey)

  /**
   * Creates new [[HOTP]] instance from `otpauth` URI.
   *
   * @see [[https://github.com/google/google-authenticator/wiki/Key-Uri-Format Key URI Format]]
   */
  def fromURI(uri: URI): HOTP = {
    import scala.util.control.Exception.allCatch
    OTPAuthURICodec.decode(uri) match {
      case Some(decoded) =>
        apply(
          decoded.params.get("algorithm").flatMap(OTPAlgorithm.find).getOrElse(OTPAlgorithm.SHA1),
          decoded.params.get("digits").flatMap(d => allCatch.opt(d.toInt)).getOrElse(6),
          decoded.otpkey)
      case None => throw new IllegalArgumentException("Illegal URI given.")
    }
  }
}
