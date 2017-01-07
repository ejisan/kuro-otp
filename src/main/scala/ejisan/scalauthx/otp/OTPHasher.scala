package ejisan.scalauthx.otp

/** Hashing helpers. */
private[otp] object OTPHasher {
  /** Calculates a hash.
    *
    * @param algorithm the name of selected hashing algorithm
    * @param secret the secret for the hashing
    * @param message the message that will be hashed
    */
  def apply(
      algorithm: OTPHashAlgorithm.Value,
      secret: OTPSecretKey,
      message: Array[Byte]): Array[Byte] = {
    val hmac = javax.crypto.Mac.getInstance(algorithm.toString)
    hmac.init(new javax.crypto.spec.SecretKeySpec(byteArray(secret), "RAW"))
    hmac.doFinal(message)
  }

  /** Converts secret to byte array */
  private def byteArray(secret: OTPSecretKey): Array[Byte] = {
    val ba = secret.value.toByteArray
    if (ba(0) == 0) ba.tail else ba
  }
}
