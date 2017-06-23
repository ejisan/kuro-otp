package ejisan.kuro.otp

/**
 * OTP Algorithm
 *
 * @param name the algorithm value that is used for otpauth URI
 * @param value the algorithm value that is used for Java `javax.crypto.Mac`
 */
sealed class OTPAlgorithm(
    val name: String,
    val value: String,
    val defaultKeyLength: Int,
    val strongKeyLength: Int) {

  override def toString: String =
    s"OTPAlgorithm($name, $value, $defaultKeyLength, $strongKeyLength)"

  override def hashCode() = {
    41 * (
      41 * (
        41 * name.hashCode + value.hashCode) +
      defaultKeyLength.hashCode) +
    strongKeyLength.hashCode
  }

  override def equals(obj: Any): Boolean = obj match {
    case a: OTPAlgorithm =>
      a.name == name &&
      a.value == value &&
      a.defaultKeyLength == defaultKeyLength &&
      a.strongKeyLength == strongKeyLength
    case _ => false
  }
}

object OTPAlgorithm {
  import scala.compat.java8.OptionConverters._

  case object MD5 extends OTPAlgorithm("MD5", "HmacMD5", 160, 160)
  case object SHA1 extends OTPAlgorithm("SHA1", "HmacSHA1", 160, 200)
  case object SHA256 extends OTPAlgorithm("SHA256", "HmacSHA256", 240, 280)
  case object SHA512 extends OTPAlgorithm("SHA512", "HmacSHA512", 480, 520)

  /**
   * JAVA API: Returns MD5 algorithm.
   */
  def getMD5(): OTPAlgorithm = MD5

  /**
   * JAVA API: Returns SHA1 algorithm.
   */
  def getSHA1(): OTPAlgorithm = SHA1

  /**
   * JAVA API: Returns SHA256 algorithm.
   */
  def getSHA256(): OTPAlgorithm = SHA256

  /**
   * JAVA API: Returns SHA512 algorithm.
   */
  def getSHA512(): OTPAlgorithm = SHA512

  /**
   * Finds [[OTPAlgorithm]] by name.
   */
  def find(name: String): Option[OTPAlgorithm] = {
    name match {
      case "MD5" => Some(MD5)
      case "SHA1" => Some(SHA1)
      case "SHA256" => Some(SHA256)
      case "SHA512" => Some(SHA512)
      case _ => None
    }
  }

  /**
   * JAVA API: Finds [[OTPAlgorithm]] by name.
   */
  def getInstanceOptionally(name: String): java.util.Optional[OTPAlgorithm] = find(name).asJava

  def unapply(algorithm: OTPAlgorithm): Option[(String, String)] =
    Some(algorithm.name -> algorithm.value)
}
