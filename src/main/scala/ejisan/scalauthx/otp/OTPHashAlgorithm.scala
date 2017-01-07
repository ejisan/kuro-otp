package ejisan.scalauthx.otp

import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac

/** Default algorithms. */
object OTPHashAlgorithm extends Enumeration {
  val SHA1 = Value("HmacSha1")
  val SHA256 = Value("HmacSha256")
  val SHA512 = Value("HmacSha512")
}

class UnsupportedOTPHashAlgorithmException(message: String)
  extends Exception(message: String)
