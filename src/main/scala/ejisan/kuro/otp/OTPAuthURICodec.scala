package ejisan.kuro.otp

import java.net.URI
import scala.collection.JavaConverters._
import scala.compat.java8.OptionConverters._

/**
 * "otpauth" URI encoder and decoder.
 *
 * @example {{{
 *  // Random key generation
 *  // Scala
 *  OTPAuthURICodec.encode(
 *    "totp",
 *    "Account Name",
 *    OTPKey.random(OTPAlgorithm.SHA1),
 *    Some("Ejisan Kuro"),
 *    Map())
 *  // => otpauth://totp/Ejisan%20Kuro:Account%20Name?secret=WBVYNT2KUJQADJGK7DFUDGWUERFZN2YS&issuer=Ejisan%20Kuro
 *
 *  // Java
 *  OTPAuthURICodec.asJava().encode(
 *    "totp",
 *    "Account Name",
 *    OTPKey.random(OTPAlgorithm.getSHA1()),
 *    Optional.of("Ejisan Kuro"),
 *    Collections.emptyMap());
 *  // => otpauth://totp/Ejisan%20Kuro:Account%20Name?secret=WBVYNT2KUJQADJGK7DFUDGWUERFZN2YS&issuer=Ejisan%20Kuro
 * }}}
 */
object OTPAuthURICodec {
  import scala.collection.immutable.Map

  final case class Decoded(
      protocol: String,
      account: String,
      otpkey: OTPKey,
      issuer: Option[String],
      params: Map[String, String]) {
    def asJava: JavaOTPAuthURICodec.Decoded = {
      new JavaOTPAuthURICodec.Decoded(protocol, account, otpkey, issuer.asJava, params.asJava)
    }
  }

  /**
   * Encodes the parameters as "otpauth" [java.net.URI]
   */
  def encode(
      protocol: String,
      account: String,
      otpkey: OTPKey,
      issuer: Option[String],
      params: Map[String, String]): URI = {
    val label = issuer.map(i => s"/$i:$account").getOrElse(s"/$account")
    val p =
      params.toSet ++
      Set("secret" -> otpkey.toBase32) ++
      issuer.map(i => Set("issuer" -> i)).getOrElse(Set())
    new URI("otpauth", protocol, label, p.map(p => s"${p._1}=${p._2}").mkString("&"), null)
  }

  /**
   * Decodes the "otpauth" [java.net.URI]
   */
  def decode(uri: URI): Option[Decoded] = {
    val scheme = uri.getScheme.toLowerCase
    val protocol = uri.getHost
    val params = uri.getQuery.split('&').map(_.split("=", 2)).collect {
      case Array(key, value) => (key, value)
      case Array(key) => (key, "")
    }.toMap
    val (account, issuer) = {
      uri.getPath.substring(1).split(":", 2) match {
        case Array(issuer, account) => (account, Some(issuer))
        case Array(account) => (account, None)
      }
    }
    if (scheme == "otpauth" && params.keys.exists(_ == "secret")) {
      val otpkey = OTPKey.fromBase32(params("secret"))
      Some(Decoded(protocol, account, otpkey, issuer, params))
    } else None
  }

  /**
   * JAVA API: Equivalent to [[JavaOTPAuthURICodec]]
   */
  def asJava: JavaOTPAuthURICodec.type = JavaOTPAuthURICodec
}

object JavaOTPAuthURICodec {
  import java.util.{ Optional, Map }

  final class Decoded(
      val protocol: String,
      val account: String,
      val otpkey: OTPKey,
      val issuer: Optional[String],
      val params: Map[String, String])

  /**
   * JAVA API: Encodes the parameters as "otpauth" [java.net.URI]
   */
  def encode(
      protocol: String,
      account: String,
      otpkey: OTPKey,
      issuer: Optional[String],
      params: Map[String, String]): URI =
    OTPAuthURICodec.encode(protocol, account, otpkey, issuer.asScala, params.asScala.toMap)

  /**
   * JAVA API: Decodes the "otpauth" [java.net.URI]
   */
  def decode(uri: URI): Optional[Decoded] =
    OTPAuthURICodec.decode(uri).map(_.asJava).asJava
}
