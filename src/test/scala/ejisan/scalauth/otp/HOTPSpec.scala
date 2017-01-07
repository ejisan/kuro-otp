package ejisan.scalauthx.otp

class HOTPSpec extends org.specs2.mutable.Specification {

  val digits = 6
  val counter = 1
  val window = 5

  val secret = OTPSecretKey.fromBase32("FVKZGY3GSHGB6LZN")
  val hotp = HOTP(OTPHashAlgorithm.SHA1, digits)

  "HOTP" should {
    "generate same code with same parameter" in {
      hotp(secret, counter) must beEqualTo (hotp(secret, counter))
    }
    s"generate $window codes with $window windows" in {
      hotp(secret, counter, window).length must beEqualTo (window)
      hotp(secret, counter, window).head._2 must beEqualTo (hotp(secret, counter))
    }
    "be able to validate" in {
      hotp.validate(hotp(secret, counter), secret, counter) must beEqualTo (true)
      hotp.validate(hotp(secret, counter + 1), secret, counter) must beEqualTo (false)
      hotp.validate("001452", secret, 3) must beEqualTo (true)
    }
    "generated code" should {
      "be same number of length as digits" in {
        hotp(secret, counter).length must beEqualTo (digits)
      }
      "be same as a code that generated with same condition" in {
        hotp(secret, counter + 1) must beEqualTo (hotp(secret, counter + 1))
      }
    }
  }
}
