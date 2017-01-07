package ejisan.scalauthx.otp

class OTPSecretKeySpec extends org.specs2.mutable.Specification {

  val secret = OTPSecretKey()

  "OTPSecretKey" should {
    "generate random secret" in {
      secret must not equalTo OTPSecretKey()
    }

    "be able to get instance from base32 encored key" in {
      secret must beEqualTo (OTPSecretKey.fromBase32(secret.toBase32))
    }
  }
}
