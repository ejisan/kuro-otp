package ejisan.scalauth.otp

import javax.crypto.spec.SecretKeySpec
import javax.crypto.Mac

/** A hashing algorithm for OTP.
  *
  * @param value the algorithm's name
  */
class OTPHashAlgorithm private (val value: String) extends AnyVal {
  override def toString: String = s"OTPHashAlgorithm($value)"
}

/** Default algorithms. */
object OTPHashAlgorithm {
  val SHA1: OTPHashAlgorithm = new OTPHashAlgorithm("HmacSha1")
  val SHA256: OTPHashAlgorithm = new OTPHashAlgorithm("HmacSha256")
  val SHA512: OTPHashAlgorithm = new OTPHashAlgorithm("HmacSha512")
}

class UnsupportedOTPHashAlgorithmException(message: String) extends Exception(message: String)
