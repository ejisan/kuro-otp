package ejisan.kuro.otp

import org.scalatest._

class HOTPSpec extends FlatSpec with Matchers {

  val otpkey = OTPKey.fromHex("3132333435363738393031323334353637383930")

  val hotp = HOTP(OTPAlgorithm.SHA1, 6, otpkey)

  // https://tools.ietf.org/html/rfc4226#page-32
  "HOTP.generate" should "generate a HOTP code (Appendix D - HOTP Algorithm: Test Values)" in {
    hotp.generate(0l) should === ("755224")
    hotp.generate(1l) should === ("287082")
    hotp.generate(2l) should === ("359152")
    hotp.generate(3l) should === ("969429")
    hotp.generate(4l) should === ("338314")
    hotp.generate(5l) should === ("254676")
    hotp.generate(6l) should === ("287922")
    hotp.generate(7l) should === ("162583")
    hotp.generate(8l) should === ("399871")
    hotp.generate(9l) should === ("520489")
  }

  it should "generate HOTP codes with window" in {
    hotp.generate(4l, 3) should === (
      Map(4l -> "338314", 5l -> "254676", 6l -> "287922", 7l -> "162583"))
  }

  // https://tools.ietf.org/html/rfc4226#page-32
  "HOTP.validate" should "validate the HOTP code (Appendix D - HOTP Algorithm: Test Values)" in {
    hotp.validate(0l, "000000") should be (false)
    hotp.validate(0l, "123456") should be (false)
    hotp.validate(Long.MaxValue, "123456") should be (false)
    hotp.validate(0l, "755224") should be (true)
    hotp.validate(1l, "287082") should be (true)
    hotp.validate(2l, "359152") should be (true)
    hotp.validate(3l, "969429") should be (true)
    hotp.validate(4l, "338314") should be (true)
    hotp.validate(5l, "254676") should be (true)
    hotp.validate(6l, "287922") should be (true)
    hotp.validate(7l, "162583") should be (true)
    hotp.validate(8l, "399871") should be (true)
    hotp.validate(9l, "520489") should be (true)
  }

  it should "validate the HOTP code with window and returns the gap" in {
    hotp.validate(0l, 0, "755224") should be (Some(0))
    hotp.validate(0l, 1, "287082") should be (Some(1))
    hotp.validate(0l, 2, "359152") should be (Some(2))
    hotp.validate(0l, 3, "969429") should be (Some(3))
    hotp.validate(0l, 4, "338314") should be (Some(4))
    hotp.validate(0l, 5, "254676") should be (Some(5))
    hotp.validate(0l, 6, "287922") should be (Some(6))
    hotp.validate(0l, 7, "162583") should be (Some(7))
    hotp.validate(0l, 8, "399871") should be (Some(8))
    hotp.validate(0l, 9, "520489") should be (Some(9))
    hotp.validate(3l, 10, "254676") should be (Some(2))
    hotp.validate(0l, 8, "520489") should be (None)
  }

  "HOTP.toURI" should "returns `otpauth` [java.net.URI]." in {
    val account = "Account Name"
    val issuer = Some("Ejisan Kuro")
    val decoded = OTPAuthURICodec.decode(hotp.toURI(account, issuer))
    decoded.get.protocol should be ("hotp")
    decoded.get.account should be (account)
    decoded.get.otpkey should be (otpkey)
    decoded.get.issuer should be (issuer)
  }
}
