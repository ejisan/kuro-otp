package ejisan.kuro.otp;

import java.util.Optional;
import java.util.Collections;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import org.junit.Test;

public class HOTPTest {

  OTPKey otpkey = OTPKey.fromHex("3132333435363738393031323334353637383930", true);

  HOTP hotp = HOTP.getInstance(OTPAlgorithm.getSHA1(), 6, otpkey);

  @Test
  public void testGenerate() throws Exception {
    assertThat(hotp.generate(0l), is ("755224"));
    assertThat(hotp.generate(2l), is ("359152"));
    assertThat(hotp.generate(4l), is ("338314"));
    assertThat(hotp.generate(6l), is ("287922"));
    assertThat(hotp.generate(8l), is ("399871"));
    assertThat(hotp.generate(9l), is (not("399871")));
    assertThat(hotp.generate(10l), is (not("000000")));
  }

  @Test
  public void testGenerateWithWindow() throws Exception {
    java.util.Map<java.lang.Long, String> codes = hotp.generateAsJava(4l, 5);
    assertThat(codes.containsKey(3l), is (false));
    assertThat(codes.get(4l), is ("338314"));
    assertThat(codes.get(5l), is ("254676"));
    assertThat(codes.get(6l), is ("287922"));
    assertThat(codes.get(7l), is ("162583"));
    assertThat(codes.get(8l), is ("399871"));
    assertThat(codes.get(9l), is ("520489"));
    assertThat(codes.containsKey(10l), is (false));
  }

  @Test
  public void testValidate() throws Exception {
    assertThat(hotp.validate(0l, "755224"), is (true));
    assertThat(hotp.validate(2l, "359152"), is (true));
    assertThat(hotp.validate(4l, "338314"), is (true));
    assertThat(hotp.validate(6l, "287922"), is (true));
    assertThat(hotp.validate(8l, "399871"), is (true));
    assertThat(hotp.validate(9l, "399871"), is (false));
    assertThat(hotp.validate(10l, "000000"), is (false));
  }

  @Test
  public void testValidateAsJava() throws Exception {
    assertThat(hotp.validateAsJava(0l, 0, "755224").isPresent(), is (true));
    assertThat(hotp.validateAsJava(0l, 2, "359152").isPresent(), is (true));
    assertThat(hotp.validateAsJava(0l, 4, "338314").isPresent(), is (true));
    assertThat(hotp.validateAsJava(0l, 6, "287922").isPresent(), is (true));
    assertThat(hotp.validateAsJava(0l, 8, "399871").isPresent(), is (true));
    assertThat(hotp.validateAsJava(0l, 7, "399871").isPresent(), is (false));
    assertThat(hotp.validateAsJava(0l, 100, "000000").isPresent(), is (false));
  }

  @Test
  public void testToURI() throws Exception {
    String account = "Account Name";
    Optional<String> issuer = Optional.of("Ejisan Kuro");
    Optional<JavaOTPAuthURICodec.Decoded> decoded =
      JavaOTPAuthURICodec.decode(hotp.toURI(account, issuer, Collections.emptyMap()));
    assertThat(decoded.get().protocol(), is ("hotp"));
    assertThat(decoded.get().account(), is (account));
    assertThat(decoded.get().otpkey(), is (otpkey));
    assertThat(decoded.get().issuer(), is (issuer));
  }
}
