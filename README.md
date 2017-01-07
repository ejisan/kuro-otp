# OTP(One time password) Authentication Library
This is the one time password authentication library for Scala. It has the implementation of TOTP ([RFC6238](https://tools.ietf.org/html/rfc6238)) and HOTP ([RFC4226](https://tools.ietf.org/html/rfc4226)), supports to generate pin code as a token and validates the pin by the user's secret.

**If you find any differences from RFC specifications, weird behavior, bugs or security vulnerability please report or issue me :) I always welcome your pull requests for implementation!**

## Secret Key and Hashing Algorithms
#### Secret Key
Prepare an OTP secret key (`OTPSecretKey`) for the user:
```scala
import ejisan.scalauthx.otp.OTPSecretKey
val secret = OTPSecretKey()
val secretFromHex = OTPSecretKey.fromHex("44360b53fc2cc239d74a")
val secretFromBase32 = OTPSecretKey.fromBase32("IQ3AWU74FTBDTV2K")
val secretFromBigInt = OTPSecretKey(BigInt("322117861288342841841482"))
```
`OTPSecretKey()` generates a secret key with a random generator that is "NativePRNGNonBlocking" as default. You can specify a random generator by giving `scala.util.Random`:
```scala
import ejisan.scalauthx.otp.OTPSecretKey
import scala.util.Random
val secret = OTPSecretKey(new Random(java.security.SecureRandom.getInstance("NativePRNGBlocking")))
```
Encoding to Base63 or Hex string representation:

```scala
import ejisan.scalauthx.otp.OTPSecretKey
val secret = OTPSecretKey()
secret.toBase32
secret.toHex
```
#### Hashing Algorithms
Create a TOTP instance with an algorithm, a length of PIN code digits and period of seconds. It supports .
```scala
import ejisan.scalauthx.otp.{ OTPHashAlgorithm, TOTP }
val totp = TOTP(OTPHashAlgorithm.SHA1, 6, 30)
```
Supported algorithms (Old versioned Google Authenticator ignores this algorithm):
- `OTPHashAlgorithm.SHA1` (Default)
- `OTPHashAlgorithm.SHA256`
- `OTPHashAlgorithm.SHA512`

## Usage of TOTP
#### PIN Code Generation
Generate PIN code as toke:
```scala
import ejisan.scalauthx.otp.{ OTPSecretKey, OTPHashAlgorithm, TOTP }
val totp = TOTP(OTPHashAlgorithm.SHA1, 6, 30)
val secret = OTPSecretKey()

totp(secret)
```
Generate PIN code with [time-step](https://tools.ietf.org/html/rfc6238#section-5.2) window:
```scala
totp(secret, 5) // Returns PIN codes that are 5 more time-step.
```
#### PIN Code Validation
Validate PIN code:
```scala
totp([pinCode], secret) // Returns boolean
```
Validate a pin code with [time-step](https://tools.ietf.org/html/rfc6238#section-5.2) window:
```scala
totp([pinCode], secret) // Returns boolean
```
### Cheat Sheet
Generate secret key.
```scala
import ejisan.scalauthx.otp.OTPSecretKey

val secret = OTPSecretKey()
secret.toBase32
```
Generate PIN code:

```scala
import ejisan.scalauthx.otp.{ OTPSecretKey, OTPHashAlgorithm, TOTP }

val secret = OTPSecretKey.fromBase32("FVKZGY3GSHGB6LZN")
val totp = TOTP(OTPHashAlgorithm.SHA1, 6, 30)

totp(secret)
```
Validate the PIN code:

```scala
val secret = OTPSecretKey.fromBase32("FVKZGY3GSHGB6LZN")
val totp = TOTP(OTPHashAlgorithm.SHA1, 6, 30)

if(totp.validate([pinCode], secret)) {
  // User is authenticated
} else {
  // User isn't authenticated
}

```

## Usage of HOTP
#### PIN Code Generation
Generate PIN code as toke with counter `1`:
```scala
import ejisan.scalauthx.otp.{ OTPHashAlgorithm, HOTP }
val hotp = HOTP(OTPHashAlgorithm.SHA1, 6)
val secret = OTPSecretKey()
val counter = 1

hotp(secret, counter)
```
Generate PIN code with [look-ahead](https://tools.ietf.org/html/rfc4226#section-7.4) window:
```scala
hotp(secret, counter, 5) // Returns 5 tuples that are (counter, PIN code).
```
#### PIN Code Validation
Validate PIN code:
```scala
hotp([pinCode], secret, counter) // Returns boolean
```
Validate a pin code with [time-step](https://tools.ietf.org/html/rfc6238#section-5.2) window:
```scala
val windowSize = 5
hotp([pinCode], secret, counter, windowSize) // Returns boolean
```
### Cheat Sheet
Generate secret key.
```scala
import ejisan.scalauthx.otp.OTPSecretKey

val secret = OTPSecretKey()
secret.toBase32
```
Generate PIN code:

```scala
import ejisan.scalauthx.otp.{ OTPSecretKey, OTPHashAlgorithm, HOTP }

val secret = OTPSecretKey.fromBase32("FVKZGY3GSHGB6LZN")
val hotp = HOTP(OTPHashAlgorithm.SHA1, 6)
val counter = 1

hotp(secret, counter)
```
Validate the PIN code:

```scala
val secret = OTPSecretKey.fromBase32("FVKZGY3GSHGB6LZN")
val hotp = HOTP(OTPHashAlgorithm.SHA1, 6)
val counter = 1

if(hotp.validate([pinCode], secret, counter)) {
  // User is authenticated
} else {
  // User isn't authenticated
}

```

## License
scalauthx-otp is licensed under the [Apache License, Version 2.0](./LICENSE).
