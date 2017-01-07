package ejisan.scalauthx.otp

class TOTPSpec extends org.specs2.mutable.Specification {
  val secret = OTPSecretKey.fromBase32("FVKZGY3GSHGB6LZN")
  val totp = TOTP(OTPHashAlgorithm.SHA1, 6, 30)

  "TOTP" should {
    "generate same code with same secret" in {
      totp(secret) must beEqualTo (totp(secret))
    }
    "generate same pin with same secret and same time" in {
      "374330" must beEqualTo (totp(secret, 1483797639006l))
    }
    "be able to validate" in {
      totp.validate(totp(secret), secret) must beEqualTo (true)
    }
  }
}
