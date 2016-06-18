package ejisan.scalauth.otp

import java.net.URI

/** OTP URI encoder */
object OTPUriEncoder {
  /** Supported algorithms */
  private val algorithms: Set[(OTPHashAlgorithm, String)] = Set(
    OTPHashAlgorithm.SHA1 -> "SHA1",
    OTPHashAlgorithm.SHA256 -> "SHA256",
    OTPHashAlgorithm.SHA512 -> "SHA512")

  private def formalizeHashAlgorithm(algorithm: OTPHashAlgorithm): String
    = algorithms.find(_._1 == algorithm).map(_._2).getOrElse(throw new UnsupportedOTPHashAlgorithmException(algorithm.toString))

  private def buildQuery(
    secret: OTPSecretKey,
    algorithm: OTPHashAlgorithm,
    digits: Int,
    issuer: String,
    additional: (String, Any)*): String
    = Set(
      "issuer" -> issuer,
      "algorithm" -> formalizeHashAlgorithm(algorithm),
      "secret" -> secret.toBase32,
      "digits" -> digits
    ).++(additional).map({case (key, value) => s"$key=$value"}).mkString("&")

  private def uri(otpType: String, query: String, label: String, account: Option[String]): URI
    = new URI("otpauth", otpType, s"/${account.map(a => s"$label:$a").getOrElse(label)}", query, null)

  /** Generates an URI for TOTP.
    *
    * @param secret the user's secret
    * @param totp the TOTP instance
    * @param label the label for the token
    * @param account the account or the user's name
    * @param issuer the issuer of the secret
    */
  def totp(
    secret: OTPSecretKey,
    totp: TOTP,
    label: String,
    account: String = "",
    issuer: String = ""): URI
    = uri("totp", buildQuery(secret, totp.algorithm, totp.digits, Option(issuer).filter(_.trim.nonEmpty).getOrElse(label), "period" -> totp.period), label, Option(account).filter(_.trim.nonEmpty))

  /** Generates an URI for HOTP.
    *
    * @param secret the user's secret
    * @param hotp the HOTP instance
    * @param counter the initial counter number
    * @param label the label for the token
    * @param account the account or the user's name
    * @param issuer the issuer of the secret
    */
  def hotp(
    secret: OTPSecretKey,
    hotp: HOTP,
    counter: Int,
    label: String,
    account: String = "",
    issuer: String = ""): URI
    = uri("hotp", buildQuery(secret, hotp.algorithm, hotp.digits, Option(issuer).filter(_.trim.nonEmpty).getOrElse(label), "counter" -> counter), label, Option(account).filter(_.trim.nonEmpty))
}
