package ejisan.kuro.otp

import org.scalatest._

class OTPAuthURICodecSpec extends FlatSpec with Matchers {

  val protocol = "totp"
  val account = "Account Name!@#$^*()_=-"
  val otpkey = OTPKey.fromBase32("GRLYIYNWQDW5YP2AXJRZZOUIBKXPBLPN")
  val issuer = Some("Ejisan Kuro!@#$^*()_=-")

  // Google Authenticator
  // Authy
  val uri = "otpauth://totp/Ejisan%20Kuro!@%23$%5E*()_=-:Account%20Name!@%23$%5E*()_=-?secret=GRLYIYNWQDW5YP2AXJRZZOUIBKXPBLPN&issuer=Ejisan%20Kuro!@%23$%5E*()_=-"

  "OTPAuthURICodec.encode" should "encodes to \"otpauth\" [[java.net.URI]]." in {
    val u = OTPAuthURICodec.encode(protocol, account, otpkey, issuer, Map())
    u.toASCIIString should be (uri)
  }

  val period = "15"
  val digits = "8"
  val algorithm = OTPAlgorithm.SHA1.name

  it should "encodes with additional parameters." in {
    val params = Map(
      "period" -> period,
      "digits" -> digits,
      "algorithm" -> algorithm)
    val decoded =
      OTPAuthURICodec.decode(OTPAuthURICodec.encode(protocol, account, otpkey, issuer, params))
    decoded.get.protocol should be (protocol)
    decoded.get.account should be (account)
    decoded.get.otpkey should be (otpkey)
    decoded.get.issuer should be (issuer)
    decoded.get.params("period") should be (period)
    decoded.get.params("digits") should be (digits)
    decoded.get.params("algorithm") should be (algorithm)
  }

  "OTPAuthURICodec.decode" should "decodes \"otpauth\" [[java.net.URI]]." in {
    val decoded = OTPAuthURICodec.decode(new java.net.URI(uri))
    decoded.get.protocol should be (protocol)
    decoded.get.account should be (account)
    decoded.get.otpkey should be (otpkey)
    decoded.get.issuer should be (issuer)
  }
}
