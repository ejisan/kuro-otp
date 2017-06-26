package ejisan.kuro.otp

import org.scalatest._

class OTPAlgorithmSpec extends FlatSpec with Matchers {

  // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
  "OTPAlgorithm#name" should "return algorithm value for otpauth URI" in {
    OTPAlgorithm.MD5.name should be ("MD5")
    OTPAlgorithm.SHA1.name should be ("SHA1")
    OTPAlgorithm.SHA256.name should be ("SHA256")
    OTPAlgorithm.SHA512.name should be ("SHA512")
  }

  "OTPAlgorithm#value" should "return algorithm value for Java [[javax.crypto.Mac]]" in {
    OTPAlgorithm.MD5.value should be ("HmacMD5")
    OTPAlgorithm.SHA1.value should be ("HmacSHA1")
    OTPAlgorithm.SHA256.value should be ("HmacSHA256")
    OTPAlgorithm.SHA512.value should be ("HmacSHA512")
  }

  "OTPAlgorithm.unapply" should "extract algorithm name and value" in {
    OTPAlgorithm.unapply(OTPAlgorithm.SHA1) should be (Some("SHA1" -> "HmacSHA1"))
  }
}
