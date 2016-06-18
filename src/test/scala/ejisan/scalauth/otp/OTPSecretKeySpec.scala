package ejisan.test.scalauth.otp

import org.specs2.mutable.Specification
import ejisan.scalauth.otp.OTPSecretKey

class OTPSecretKeySpec extends Specification {

  val secret = OTPSecretKey()

  "OTPSecretKey" should {
    "generates random secret" in {
      secret must not equalTo OTPSecretKey()
    }

    "be able to get instance from base32 encored key" in {
      secret must beEqualTo (OTPSecretKey.fromBase32(secret.toBase32))
    }
  }
}
