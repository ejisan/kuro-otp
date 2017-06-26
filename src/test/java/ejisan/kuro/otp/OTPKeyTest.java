package ejisan.kuro.otp;

import java.security.Key;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;

public class OTPKeyTest {

  @Test
  public void testGetInstance() throws Exception {
    KeyGenerator gen = KeyGenerator.getInstance("hmacSHA1");
    gen.init(128);
    OTPKey key1 = OTPKey.getInstance((Key) gen.generateKey(), true);
    OTPKey key2 = OTPKey.getInstance((Key) (new SecretKeySpec(key1.toByteArray(), "RAW")), true);
    assertThat(key1, is (key2));
  }

  @Test(expected = IllegalArgumentException.class)
  public void testLengthValidation128() throws Exception {
    KeyGenerator gen = KeyGenerator.getInstance("hmacSHA1");
    gen.init(120);
    OTPKey.getInstance((Key) gen.generateKey(), true);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testLengthValidation80() throws Exception {
    KeyGenerator gen = KeyGenerator.getInstance("hmacSHA1");
    gen.init(72);
    OTPKey.getInstance((Key) gen.generateKey(), false);
  }

  @Test
  public void testByteArray() throws Exception {
    OTPKey key = OTPKey.random(OTPAlgorithm.getSHA1());
    assertThat(OTPKey.fromByteArray(key.toByteArray(), true), is (key));
  }

  @Test
  public void testHex() throws Exception {
    OTPKey key = OTPKey.random(OTPAlgorithm.getSHA1());
    assertThat(OTPKey.fromHex(key.toHex(), true), is (key));
  }

  @Test
  public void testBase64() throws Exception {
    OTPKey key = OTPKey.random(OTPAlgorithm.getSHA1());
    assertThat(OTPKey.fromBase64(key.toBase64(), true), is (key));
    assertThat(OTPKey.fromBase64(key.toBase64WithoutPadding(), true), is (key));
  }

  @Test
  public void testBase64URL() throws Exception {
    OTPKey key = OTPKey.random(OTPAlgorithm.getSHA1());
    assertThat(OTPKey.fromBase64URL(key.toBase64URL(), true), is (key));
    assertThat(OTPKey.fromBase64URL(key.toBase64URLWithoutPadding(), true), is (key));
  }

  @Test
  public void testBase32() throws Exception {
    OTPKey key = OTPKey.random(OTPAlgorithm.getSHA1());
    assertThat(OTPKey.fromBase32(key.toBase32(), true), is (key));
    assertThat(OTPKey.fromBase32(key.toBase32WithoutPadding(), true), is (key));
  }

  @Test
  public void testBase32Hex() throws Exception {
    OTPKey key = OTPKey.random(OTPAlgorithm.getSHA1());
    assertThat(OTPKey.fromBase32Hex(key.toBase32Hex(), true), is (key));
    assertThat(OTPKey.fromBase32Hex(key.toBase32HexWithoutPadding(), true), is (key));
  }

  @Test
  public void testRandom() throws Exception {
    OTPKey md5Key = OTPKey.random(OTPAlgorithm.getMD5());
    assertThat(md5Key.keyLength(), is (OTPAlgorithm.getMD5().defaultKeyLength()));
    OTPKey sha1Key = OTPKey.random(OTPAlgorithm.getSHA1());
    assertThat(sha1Key.keyLength(), is (OTPAlgorithm.getSHA1().defaultKeyLength()));
    OTPKey sha256Key = OTPKey.random(OTPAlgorithm.getSHA256());
    assertThat(sha256Key.keyLength(), is (OTPAlgorithm.getSHA256().defaultKeyLength()));
    OTPKey sha512Key = OTPKey.random(OTPAlgorithm.getSHA512());
    assertThat(sha512Key.keyLength(), is (OTPAlgorithm.getSHA512().defaultKeyLength()));
  }

  @Test
  public void testRandomStrong() throws Exception {
    OTPKey md5Key = OTPKey.randomStrong(OTPAlgorithm.getMD5());
    assertThat(md5Key.keyLength(), is (OTPAlgorithm.getMD5().strongKeyLength()));
    OTPKey sha1Key = OTPKey.randomStrong(OTPAlgorithm.getSHA1());
    assertThat(sha1Key.keyLength(), is (OTPAlgorithm.getSHA1().strongKeyLength()));
    OTPKey sha256Key = OTPKey.randomStrong(OTPAlgorithm.getSHA256());
    assertThat(sha256Key.keyLength(), is (OTPAlgorithm.getSHA256().strongKeyLength()));
    OTPKey sha512Key = OTPKey.randomStrong(OTPAlgorithm.getSHA512());
    assertThat(sha512Key.keyLength(), is (OTPAlgorithm.getSHA512().strongKeyLength()));
  }
}
