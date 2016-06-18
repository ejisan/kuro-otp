package ejisan.scalauth.otp

import scala.math.BigInt

/** A secret that is used in OTP.
  *
  * @constructor create a new secret with a value as bytes.
  * @param value the secret's bytes
  */
final class OTPSecretKey private (val value: BigInt) extends AnyVal {
  /** Converts this secret key to hex encoded string representation */
  def toHex: String = toString(16)
  /** Converts this secret key to base32 encoded string representation */
  def toBase32: String = Base32.encode(value)
  def toString(n: Int): String = value.toString(n)
  override def toString: String = s"OTPSecretKey($toBase32)"
}

/** Factory for [[ejisan.scalauth.otp.OTPSecretKey]] instances. */
object OTPSecretKey {
  import scala.util.Random

  /** Creates a secret with a random value. */
  def apply(): OTPSecretKey
    = apply(new Random(java.security.SecureRandom.getInstance("NativePRNGNonBlocking")))

  /** Creates a secret with a pseudo random number generator.
    *
    * @param prng the pseudo random number generator
    */
  def apply(prng: Random): OTPSecretKey
    = new OTPSecretKey((2 to 16).foldLeft(BigInt(prng.nextInt(31)) + 1: BigInt)((a, b) => a * 32 + prng.nextInt(32)))

  /** Creates a secret with a value as bytes.
    *
    * @param value the secret's bytes
    */
  def apply(value: BigInt): OTPSecretKey = new OTPSecretKey(value)

  /** Creates a secret with a hex encoded secret string.
    *
    * @param value the hex encoded secret string
    */
  def fromHex(hex: String): OTPSecretKey = apply(BigInt(hex, 16))

  /** Creates a secret with a base32 encoded secret string.
    *
    * @param base32 the base32 encoded secret string
    */
  def fromBase32(base32: String): OTPSecretKey = apply(Base32.decode(base32))
}
