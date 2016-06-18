package ejisan.test.scalauth.otp

import org.specs2.mutable.Specification
import ejisan.scalauth.otp.{ TOTP, OTPSecretKey, OTPHashAlgorithm }

class TOTPSpec extends Specification {
  val secret = OTPSecretKey.fromBase32("FVKZGY3GSHGB6LZN")
  val totp = TOTP(OTPHashAlgorithm.SHA1, 6, 30)

  "TOTP" should {
    "generates same code with same secret" in {
      totp(secret) must beEqualTo (totp(secret))
    }
    "be able to validate" in {
      totp.validate(totp(secret), secret) must beEqualTo (true)
    }
  }
}
