package ejisan.scalauth.otp

/** Default instances for Google Authenticator.
  *
  * {{{
  * val secret: OTPSecretKey = OTPSecretKey()
  * val counterForHOTP: Int = 1
  *
  * // PIN Code generation
  * val pin1: String = GoogleAuthenticator.hotp(secret, counterForHOTP)
  * val pin2: String = GoogleAuthenticator.totp(secret)
  *
  * // PIN Code validation
  * GoogleAuthenticator.hotp.validate(pin1, secret, counterForHOTP)
  * GoogleAuthenticator.totp.validate(pin2, secret)
  * }}}
  */
object GoogleAuthenticator {
  /** Creates a HOTP utility with a given algorithm and digits.
    *
    * @param algorithm the name of selected hashing algorithm
    * @param digits the length of returning OTP pin code string
    */
  def hotp(algorithm: OTPHashAlgorithm.Value = OTPHashAlgorithm.SHA1, digits: Int = 6): HOTP = {
    require(digits >= 6, s"`digits` must be greater than or equal to 6, but it is '$digits'.")
    HOTP(algorithm, digits)
  }

  /** Default HOTP instance for Google Authenticator.
    * It configured with digits: 6.
    */
  val hotp: HOTP = hotp()

  /** Creates a TOTP utility with a given algorithm, digits and period.
    *
    * @param algorithm the name of selected hashing algorithm
    * @param digits the length of returning OTP pin code string
    * @param period the period of seconds
    */
  def totp(algorithm: OTPHashAlgorithm.Value = OTPHashAlgorithm.SHA1, digits: Int = 6, period: Int = 30): TOTP = {
    require(digits >= 6, s"`digits` must be greater than or equal to 6, but it is '$digits'.")
    require(period >= 5, s"`period` must be greater than or equal to 5, but it is '$period'.")
    TOTP(algorithm, digits, period)
  }

  /** Default TOTP instance for Google Authenticator.
    * It configured with digits: 6 and period 30.
    */
  val totp: TOTP = totp()
}
