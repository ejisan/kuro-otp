package ejisan.kuro.otp;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;

public class OTPAlgorithmTest {

  @Test
  public void testAlgorithmValue() throws Exception {
    assertThat(OTPAlgorithm.getMD5().value(), is ("HmacMD5"));
    assertThat(OTPAlgorithm.getSHA1().value(), is ("HmacSHA1"));
    assertThat(OTPAlgorithm.getSHA256().value(), is ("HmacSHA256"));
    assertThat(OTPAlgorithm.getSHA512().value(), is ("HmacSHA512"));
  }

  @Test
  public void testAlgorithmName() throws Exception {
    assertThat(OTPAlgorithm.getMD5().name(), is ("MD5"));
    assertThat(OTPAlgorithm.getSHA1().name(), is ("SHA1"));
    assertThat(OTPAlgorithm.getSHA256().name(), is ("SHA256"));
    assertThat(OTPAlgorithm.getSHA512().name(), is ("SHA512"));
  }
}
