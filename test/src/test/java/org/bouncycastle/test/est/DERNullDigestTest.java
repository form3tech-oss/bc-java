package org.bouncycastle.test.est;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Date;

import static org.junit.Assert.assertEquals;

@RunWith(PowerMockRunner.class)
@PrepareForTest({DefaultSignedAttributeTableGenerator.class})
public class DERNullDigestTest {

    private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIJKgIBAAKCAgEAs/M1uLb6Lr4CM60DpribvX7Htg59wapBzE7yXtGY8cdMS4qr\n" +
            "4mzVbaUGjIZ7L0uEQRgoaby4QdeuPIPMRCEXuTCMhRI1YiDWWAPeFqBM4ilFH5gK\n" +
            "4pD8F+jpsVMNLwMRRycSAVSYVLlIRZnUx8sBzPcnRW0xGlovwvYrR/ABmt8sUpqM\n" +
            "e7zIoSGYL8QbR74x5Rsv81EKuY2llwzBQcaXAoTM9oG5rVhyaTpCdSqfMztxkENF\n" +
            "xrPXBmBEnm42hiXq4UpCz7HpICWHV8H+eIq8qmHLXJ11IGvcNfilQDsTLovR9xey\n" +
            "qNd0sEf78Hq3dAI0f/fuz+DXsyzzHM+6AT87gIyB5ey2JIIxB9TQDF3Ez9zW+JSq\n" +
            "8HZJZsfYyIWE6xeLzdYDeFQz6HDBRBWkh3QsZSVCkmdjYxNJMWNEgJukyL/+6yqN\n" +
            "SpV8P2p+lt/VaKxurW769TQsPeo5Aseywwtx8E+tYy9p4T71SgFSn54cJWaNE9Gx\n" +
            "pa2+zs8Zu0FIyMqGVan9BRAPgHLiNnkcCAk4qHYwP4uS3fjO6lR+FTnVuWjb6uyt\n" +
            "AqfNrCFHtkY64wQHiHtfcUCf1qhDx5zJAfSjEE5HXy2r+2VAgmZkz/W4n2gSczLx\n" +
            "4MzzZu5P1man6SCpO9o4uOLXKiJONC9WXHsgOu6ZEyP/KXSV0+kmqjZkrWMCAwEA\n" +
            "AQKCAgEAia3FJoRouiaKTLtNFdwc3EkJx9MiiHAZU5X7fmxi1mmjiBCbHewjB3bB\n" +
            "ofaqfS8MCznOgcfwOgAowQgd2upu2jO4739U9LUnCcQ7wZf3+vmUd22+tkYzep+r\n" +
            "XQ6sAZIZQBU2g2oT+o6gKxBdald6EzXuCAJZFU53SHVL/Ag3UiT6JmE0pt9zqUSo\n" +
            "ybMDJErypdW9RC53RCyJyx3pJsgodbbhkqECTQxkzPnUKwznLS2H39Z4pmSmWayC\n" +
            "E61DbjPIl4JXx8zZDs1n1c8JQXT0kG+uRjf6i0m6/Fg3JwOL04sKpECvYtsl3lHV\n" +
            "AtMBVXLydA5f2xCuN9pmT17nc1jLznBAupLC60YNyGXmBKJvxBFE7X9IzIrRCA8K\n" +
            "z2hLhkibAZYbhgsfC2ZjzMTBtUTUh+OWOhBBpl3gI+av4u5pD+Vww5/UiICM4cq9\n" +
            "Oh0N5LlGHHueUlArUh+6VhXGQPbd6ba1eIG4jlkaI8C26PVOMnk5vVcLNWpygqcJ\n" +
            "M9+P27iYjdIX9Kaye7jj1dr36momJcY+06srVnhyIYRyZ6ALd+5FiMOL0U5rOwOM\n" +
            "c6OWODc0obT6seboGmyJ3RHfHJ4vAQlVBWfQ1IDHz9Yhzd39feDw7vwczd1ZEm7X\n" +
            "5vHYP/F9I9KItxoAj7h19DEs2mGtjoEE0jh1pkM4JalK4oHs8VECggEBANhUQP5a\n" +
            "X17REjuOwgw3SvcpRXZhoNMzthQoBJ6eG76D3qHmAnWS3gpL9VBxF263xA0anD65\n" +
            "WgUC6TRHzkDh+IIVp1bZV/pXrjnRSLeFvqgleKmu8hSBx1g+T1jy3hfTETFsz3W3\n" +
            "kdN6Ne4/9ANqcOgA7Tl3c4SAfu+rY+zWtlUYIF9IJi4ZkKAkT45tAGT1M828MTi2\n" +
            "nTitBZbdhnN6zsiagWHf1TZZU+Qty7eBlZxEXUQxcJzpwI20dVvdn+616sR8Ykut\n" +
            "2KWepFgBWKOOj7Xt5t58lPRNn8553KQgPaAe4F5+6CKJ493jx9uj3QA3M7EkCJjC\n" +
            "M6QWumD3n/vOH+UCggEBANTzHE989KUe4eIBnJ3t1kDOflYo0hBqhM3wQ+GJO79B\n" +
            "x1rErM0xfjTBUptX9lLoNDQiNuy8v7ulABbzlIlyGqg0T3RKX9uzLrT8ZTZkYiVQ\n" +
            "dQpEo+S1nLFYW28DanmlTTCIu2OXiWEVX1sZEwUrJ+RMiyYI74vZ9n+KTe6NJ8RJ\n" +
            "5U5FdGDrIaVYkHIk3jHjICEdGXlfAbLdgBu+C/WbJ28PyBHziTAUthq71hL0/zPD\n" +
            "favedE0xhTTUzyVMO1O51IMikvMYTg4vFRgCVszKnqhq8XROsEfpfPO7mgh1gXG/\n" +
            "2JmxQBFeY7iENnqDnxxwOzDRxWtJ35ngMQ+cBeKSc6cCggEBAId24ygj0VrfkwpG\n" +
            "kA70RPZXGs9RvVLkK92dXZ8yJO99RlmdXebgLDjIbfqMhv7nBlaqVjMVAGDo/L2n\n" +
            "RWnt1x8mjh5dhbEXXNuJyX5auxQyOsgO7DqZNgp1Ilzx4M+MdVS87YCqjh+ehM0H\n" +
            "sTa+Xat6gRKeUXEkwdg1PCKgJZdNv1/LH1V43s7ZThRC/584yNLJSQ1ZlURbXIen\n" +
            "er0vpvOJhQGUF8Cr2VOmtc3Y0KYFTV4Zk4o++jwCSAdZ1f+2XSfjN+5qE6NKn2EY\n" +
            "nrf02tsy+YJTAzeksDCssNT5930gOKIT2Ctgq5dUPt+0Uf0DlFQV22hFG+9h6B42\n" +
            "kjEtV10CggEAfUiOZmGQmTjDEjF6kBumSrhx8YTQmaHhgjuR5DXV9d7gR5GgTJSK\n" +
            "uMToMcadgAdm9ykOAVfGwcIAfIBP6lE8R6uG91bucJZJq2c2sLp8V5GvWhwqBFuo\n" +
            "1VmzaWusD+dls2EuRhiYVYq6cCEfZJIQRSuXTghBzpisgjq/QNLBC6WiB9uq7X5I\n" +
            "bDvft5fjNZx3gaPaIeL4X+AbB7dW1+exWpEBVzZdhvEYdj/+YWbMYgroe95DtEqn\n" +
            "IP724+2mlcqlsYT8yZKKEaQ3l8mAgbnPgCxy48eLxLMktUyxAbsILgD9kOaMV+ud\n" +
            "Zag7WPbo/FU3LbCsokNzDtesZY+YksUwzwKCAQEAiduA/Q2MW41GC3x6tqgb8cJG\n" +
            "z8kYleRF27fLhUQNoeJltZde/YK0wa/3NVZMKgnoBBgmZYwCH34kwgC0g3qwKT+5\n" +
            "FLn+8kn8X7OMEvXIlXjaJuds87INsnwfL4o8Jt+IBm8L6VG8HV4rQ802ghmJC/Aw\n" +
            "Q643sShBf5RgPGiYiZF8rHLwvqkOCECrnYiYwnlfa+YnNxCMhYpRCbeno+iidNRb\n" +
            "GoXj44a1/4YuwJCN/5gfnqgI0IlNcP+Fc4VEK7A5zScGQD0/11kVJzS0tY2pGdEB\n" +
            "d5IYkvhXsWr0N9r0KWh+An/pq7a1gOYWY17ZbVFaEYmk+dsW1KpY84gnG4NnkQ==\n" +
            "-----END RSA PRIVATE KEY-----\n";
    private static final String SIGNING_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
            "MIIE2DCCAsACCQDo3EcopQVGtTANBgkqhkiG9w0BAQsFADAuMQswCQYDVQQGEwJV\n" +
            "SzEPMA0GA1UEBwwGTG9uZG9uMQ4wDAYDVQQKDAVGb3JtMzAeFw0yMTA2MjUwOTMw\n" +
            "MjNaFw0yMjA2MjUwOTMwMjNaMC4xCzAJBgNVBAYTAlVLMQ8wDQYDVQQHDAZMb25k\n" +
            "b24xDjAMBgNVBAoMBUZvcm0zMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\n" +
            "AgEAs/M1uLb6Lr4CM60DpribvX7Htg59wapBzE7yXtGY8cdMS4qr4mzVbaUGjIZ7\n" +
            "L0uEQRgoaby4QdeuPIPMRCEXuTCMhRI1YiDWWAPeFqBM4ilFH5gK4pD8F+jpsVMN\n" +
            "LwMRRycSAVSYVLlIRZnUx8sBzPcnRW0xGlovwvYrR/ABmt8sUpqMe7zIoSGYL8Qb\n" +
            "R74x5Rsv81EKuY2llwzBQcaXAoTM9oG5rVhyaTpCdSqfMztxkENFxrPXBmBEnm42\n" +
            "hiXq4UpCz7HpICWHV8H+eIq8qmHLXJ11IGvcNfilQDsTLovR9xeyqNd0sEf78Hq3\n" +
            "dAI0f/fuz+DXsyzzHM+6AT87gIyB5ey2JIIxB9TQDF3Ez9zW+JSq8HZJZsfYyIWE\n" +
            "6xeLzdYDeFQz6HDBRBWkh3QsZSVCkmdjYxNJMWNEgJukyL/+6yqNSpV8P2p+lt/V\n" +
            "aKxurW769TQsPeo5Aseywwtx8E+tYy9p4T71SgFSn54cJWaNE9Gxpa2+zs8Zu0FI\n" +
            "yMqGVan9BRAPgHLiNnkcCAk4qHYwP4uS3fjO6lR+FTnVuWjb6uytAqfNrCFHtkY6\n" +
            "4wQHiHtfcUCf1qhDx5zJAfSjEE5HXy2r+2VAgmZkz/W4n2gSczLx4MzzZu5P1man\n" +
            "6SCpO9o4uOLXKiJONC9WXHsgOu6ZEyP/KXSV0+kmqjZkrWMCAwEAATANBgkqhkiG\n" +
            "9w0BAQsFAAOCAgEAIcZ3QbFlb8ZiA+0QlWWsx+E7mo3KEJ3IYD1LQFv7zMh1g1EJ\n" +
            "S9L+HsaMWAYCvfcquWOK7jKJVc1orrGdHMb+Kg9H1qxlQCnzN7reIPRVOB0XnxDr\n" +
            "XCCXd1mlntkKZtm79G3BFix4B6b4R8DlD0orH4JDTfKHvzMajZ1F2gy+8WFDwuMP\n" +
            "+O37UFXU5XaM+mcel0zXe2/gx/pGOQAECC+fWfVjE018EVUx2zSb05MNXiKCl4qS\n" +
            "fXQJEsMeqDJll+2BDBYQJF6+FZK+atfI0PP2Q+igT6RIt2vB4JrLRGEz4EE6aXf9\n" +
            "amd20bl5WMPf3DaNDoS9PXccCSRC8sWUVdRopjHAP/HV2pczVIAZDQdpvscFGvlm\n" +
            "6hkyGsTmXr0FShM7uH+31gvaVbBG20lTIB3FzaE3hX7F8kTIOhbrxAGxL1jJfBrA\n" +
            "gIl9xrAM25JANGdTCeSZwcbdkLZ8s+tYsJGFGaLsfXL+8jMmFv44X6nPzCB/oAvx\n" +
            "3Rs0rxmjOCHT8m6ZMWhqv0ecC3qTZWm/+KE0nvvfCEa6ekq8LeWVqkEepJF5cyC3\n" +
            "ibrPJJHwcyA6ATf1KBNqy5nCqZQFr2UXSugNjWS188uytNwQly+fMLEBznBmJhZm\n" +
            "WkplyIVm2sEVIglAR+qcWSHlbnRlieDKDYDzvowy809jhuQFKXOEF4WRI/E=\n" +
            "-----END CERTIFICATE-----\n";

    private static long SOME_FIXED_DATE = 1000000L;

    private final String EXPECTED_SIGNATURE = "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";

    @Test
    public void testSignatureDoesNotChangeWithVersions() throws Exception {
        Date fixedDate = new Date(SOME_FIXED_DATE);
        PowerMockito.whenNew(Date.class).withAnyArguments().thenReturn(fixedDate);

        Security.addProvider(new BouncyCastleProvider());

        java.security.cert.Certificate signingCertificate = generateCertificate();

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(new BouncyCastleProvider())
                .build(getPrivateKeyFromString(PRIVATE_KEY));

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        X509CertificateHolder signingCertificateHolder = new X509CertificateHolder(Certificate.getInstance(signingCertificate.getEncoded()));
        generator.addCertificate(signingCertificateHolder);
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder()
                                .setProvider("BC")
                                .build())
                        .build(signer, signingCertificateHolder));

        CMSProcessableByteArray cmsData = new CMSProcessableByteArray("data to be signed".getBytes(StandardCharsets.UTF_8));
        CMSSignedData signedData = generator.generate(cmsData, false);

        byte[] signedDataEncoded = signedData.getEncoded();
        ASN1Primitive resultPrimitive = new ASN1InputStream(new ByteArrayInputStream(signedDataEncoded)).readObject();
        ASN1Primitive expectedPrimitive = new ASN1InputStream(new ByteArrayInputStream(Base64.getDecoder().decode(EXPECTED_SIGNATURE))).readObject();
        assertEquals(resultPrimitive, expectedPrimitive);
    }

    public PrivateKey getPrivateKeyFromString(String privateKey) throws IOException {
        Reader rdr = new StringReader(privateKey);
        Object parsed = new org.bouncycastle.openssl.PEMParser(rdr).readObject();
        KeyPair pair = new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter().getKeyPair((org.bouncycastle.openssl.PEMKeyPair) parsed);
        return pair.getPrivate();
    }

    private java.security.cert.Certificate generateCertificate() {
        try {
            CertificateFactory certFactory = getCertFactoryInstance();
            return certFactory.generateCertificate(IOUtils.toInputStream(SIGNING_CERTIFICATE, Charset.defaultCharset()));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Certificate format not valid", e);
        }
    }

    public CertificateFactory getCertFactoryInstance() throws CertificateException {
        return CertificateFactory.getInstance("X.509");
    }

}