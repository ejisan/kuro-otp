package ejisan.scalauth.otp

/** A HOTP(HMAC-based One-time Password Algorithm).
  *
  * {{{
  * import ejisan.scalauth.otp._
  *
  * val secret: OTPSecretKey = OTPSecretKey()
  * val hotp: HOTP = HOTP(OTPHashAlgorithm.SHA1)
  * val counter: Int = 1
  *
  * // Pin code generation
  * hotp(secret, counter) // : String
  * hotp(secret, counter, 5) // : Seq[String]
  *
  * // Pin code validation
  * hotp.validate(pin, secret, counter) // : Boolean
  * hotp.validate(pin, secret, counter, 5) // : Boolean (Look-ahead 5 more count)
  * }}}
  *
  * @param algorithm the name of selected hashing algorithm
  * @param digits the length of returning OTP pin code string
  */
class HOTP private (val algorithm: OTPHashAlgorithm.Value, val digits: Int) {
  /** Generates OTP pin code with a given user's secret and a counter.
    *
    * @param secret the user's secret
    * @param counter the counter number
    *
    * @return pin code digits
    */
  def apply(secret: OTPSecretKey, counter: Long): String
    = HOTP(algorithm, digits, secret, counter)

  /** Generates OTP pin codes with a given user's secret, a counter and a window size.
    *
    * @param secret the user's secret
    * @param counter the counter number
    * @param window the look-ahead window size
    *
    * @return a sequence of tuple typed (Long, String) as (counter, pin code digits)
    */
  def apply(secret: OTPSecretKey, counter: Long, window: Int): Seq[(Long, String)]
    = (counter until counter + window).map(c => (c, HOTP(algorithm, digits, secret, c)))

  /** Validates a given OTP pin code with a given user's secret and a counter.
    *
    * @param pin the pin code that user generated
    * @param secret the user's secret
    * @param counter the counter number
    */
  def validate(pin: String, secret: OTPSecretKey, counter: Long): Boolean
    = pin == apply(secret, counter)

  /** Validates a given OTP pin code with a given user's secret, a counter and a window size.
    *
    * @param pin the pin code that user generated
    * @param secret the user's secret
    * @param counter the counter number
    * @param window the look-ahead window size
    *
    * @return an optional matched counter number
    */
  def validate(pin: String, secret: OTPSecretKey, counter: Long, window: Int): Option[Long]
    = apply(secret, counter, window).find(_._2 == pin).map(_._1)
}

/** Factory for [[ejisan.scalauth.otp.HOTP]] instances
  * and an implementation of HOTP pin code generation.
  **/
object HOTP {
  /** An implementation of HOTP pin code generation.
    *
    * @param algorithm the name of selected hashing algorithm
    * @param digits the length of returning OTP pin code string
    * @param secret the user's secret
    * @param counter the counter number
    *
    * @return pin code digits
    */
  def apply(algorithm: OTPHashAlgorithm.Value, digits: Int, secret: OTPSecretKey, counter: Long): String = {
    val msg = BigInt(counter).toByteArray.reverse.padTo(8, 0.toByte).reverse
    val hash = OTPHasher(algorithm, secret, msg)
    val offset = hash(hash.length - 1) & 0xf
    val binary = ((hash(offset) & 0x7f) << 24) |
      ((hash(offset + 1) & 0xff) << 16) |
      ((hash(offset + 2) & 0xff) << 8 |
       (hash(offset + 3) & 0xff))
    val otp = binary % (scala.math.pow(10, digits)).toLong
    ("0" * digits + otp.toString).takeRight(digits)
  }

  /** Creates a HOTP with a given algorithm and digits.
    *
    * @param algorithm the name of selected hashing algorithm
    * @param digits the length of returning OTP pin code string
    */
  def apply(algorithm: OTPHashAlgorithm.Value, digits: Int): HOTP = {
    // Requirements
    require(digits > 0, s"digits must be greater than 0, but it is ($digits)")
    new HOTP(algorithm, digits)
  }
}
