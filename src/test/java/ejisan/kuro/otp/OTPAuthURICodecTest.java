package ejisan.kuro.otp;

import java.net.URI;
import java.util.Collections;
import java.util.Optional;
import java.util.Map;
import java.util.HashMap;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import org.junit.Test;

public class OTPAuthURICodecTest {

  String protocol = "totp";
  String account = "Account Name!@#$^*()_=-";
  OTPKey otpkey = OTPKey.fromBase32("GRLYIYNWQDW5YP2AXJRZZOUIBKXPBLPN", true);
  Optional<String> issuer = Optional.of("Ejisan Kuro!@#$^*()_=-");

  String uri = "otpauth://totp/Ejisan%20Kuro!@%23$%5E*()_=-:Account%20Name!@%23$%5E*()_=-?secret=GRLYIYNWQDW5YP2AXJRZZOUIBKXPBLPN&issuer=Ejisan%20Kuro!@%23$%5E*()_=-";

  @Test
  public void testEncode() throws Exception {
    URI u1 = OTPAuthURICodec.asJava().encode(protocol, account, otpkey, issuer, Collections.emptyMap());
    URI u2 = JavaOTPAuthURICodec.encode(protocol, account, otpkey, issuer, Collections.emptyMap());
    assertThat(u1.toASCIIString(), is (uri));
    assertThat(u2.toASCIIString(), is (uri));
  }

  String period = "15";
  String digits = "8";
  String algorithm = OTPAlgorithm.getSHA1().name();

  public void testEncodeWithParams() throws Exception {
    Map<String, String> params = new HashMap();
    params.put("period", period);
    params.put("digits", digits);
    params.put("algorithm", algorithm);

    Optional<JavaOTPAuthURICodec.Decoded> d1 =
      OTPAuthURICodec.asJava().decode(OTPAuthURICodec.asJava().encode(protocol, account, otpkey, issuer, params));
    Optional<JavaOTPAuthURICodec.Decoded> d2 =
      JavaOTPAuthURICodec.decode(JavaOTPAuthURICodec.encode(protocol, account, otpkey, issuer, params));

    assertThat(d1.get().protocol(), is (protocol));
    assertThat(d1.get().account(), is (account));
    assertThat(d1.get().otpkey(), is (otpkey));
    assertThat(d1.get().issuer(), is (issuer));
    assertThat(d1.get().params().get("period"), is (period));
    assertThat(d1.get().params().get("digits"), is (digits));
    assertThat(d1.get().params().get("algorithm"), is (algorithm));

    assertThat(d2.get().protocol(), is (protocol));
    assertThat(d2.get().account(), is (account));
    assertThat(d2.get().otpkey(), is (otpkey));
    assertThat(d2.get().issuer(), is (issuer));
    assertThat(d2.get().params().get("period"), is (period));
    assertThat(d2.get().params().get("digits"), is (digits));
    assertThat(d2.get().params().get("algorithm"), is (algorithm));
  }
}
