package ejisan.scalauthx.otp

import scala.math.BigInt

/** Base32 encoder and decoder */
private[otp] object Base32 {
  private val alphabet: String =
    new String((('A' to 'Z') ++ ('2' to '7')).toArray)

  /** Encodes BigInt to base32 encoded string */
  def encode(value: BigInt): String =
    new String(
      value
        .toString(32)
        .toCharArray
        .map(_.asDigit)
        .map(alphabet(_)))

  /** Decodes base32 encoded string to BigInt */
  def decode(value: String): BigInt =
    BigInt(
      value
        .toCharArray
        .map(alphabet.indexOf(_))
        .map(BigInt(_))
        .map(_.toString(32))
        .mkString,
      32)
}
