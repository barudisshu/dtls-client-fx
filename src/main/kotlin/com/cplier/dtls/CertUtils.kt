package com.cplier.dtls

import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.Arrays
import org.bouncycastle.util.io.pem.PemReader
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.StringReader
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*


fun rootCertificate(crypto: BcTlsCrypto): Certificate {
  val rootX509 = readX509FromString(
    """
        -----BEGIN CERTIFICATE-----
        MIIEFjCCAv6gAwIBAgIJAMZsNQLY2tiJMA0GCSqGSIb3DQEBCwUAMIGeMQswCQYD
        VQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3Ux
        FzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEVMBMG
        A1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmlj
        c3Nvbi5jb20wIBcNMjEwODA1MDgyMzQ5WhgPMzAyMDEyMDYwODIzNDlaMIGeMQsw
        CQYDVQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3po
        b3UxFzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEV
        MBMGA1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBl
        cmljc3Nvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6IiM0
        J0Aef5zpCCzofBv8vl3x2gjWZMovDo8bPz7gtrhanH+cQZQzYrcGujmPgAbe3UTn
        IJR9aElb2fBJr7oD5jZLMT13tHNaOvzHLZzQ57zL5Negsp/X67VCO8uat+MX71O4
        pol5YZMdcPbRNuqHn3plXj285oiPYkd6nX0IeSHN2XE2Utk9UmI0v7XYnnFagrYr
        H8pFo63IU2JvJeCbSCw4hZN+GY/DZm8umBqCz27Cyz8wkqFDlNdHOdJJgnBArBxD
        9ykZwnWuDjtEkUJNzi6XH9Cf2hlc1ylK1MFlovXYtgaw9vCo3Fdtxy4paJHrxh7H
        9FY/3BuZ2Y9QaH1TAgMBAAGjUzBRMB0GA1UdDgQWBBQ0tkEoZvnMT9sSOJ7jDU3n
        /GfuHDAfBgNVHSMEGDAWgBQ0tkEoZvnMT9sSOJ7jDU3n/GfuHDAPBgNVHRMBAf8E
        BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCMF6QlDn9SCb7Wjrar3Ejji11zSNBe
        ErEu+tFi3KrmnjhjUPQ/2OaW17AkqEXdV3fAzOYoZvayte3J6vIs5sgWKUjAIfHt
        6eXiaBesbkbKQ3lgvQnMOUdh6BoV9euY4NhBb1BUjvypnp/CVb5/vAqFUg921nWd
        iRYtmNPIYlq7DANxiSK+lgljgXlPL8lGNWvSm/ChQvEdV32L0WrYUiPaeDgsBSUO
        3lnSxGd90hrlUXS6Ms8CZChaDzEBc9tJCYRSc9Z8dYyWlc6ts/46xIIb8JBAtkSH
        YwMvcfbA0sYViKyryA50FYhR9r8HLkgas6GKFbYyQF3h+1yXwjMK0/uU
        -----END CERTIFICATE-----

        """.trimIndent()
  )

  return x509CertsToBcCert(crypto, rootX509)
}

fun serverPrivateKey(): AsymmetricKeyParameter {
  val serverPk = readPrivateFromString(
    """
      -----BEGIN PRIVATE KEY-----
      MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDKLudgZKeTUzIe
      HsTYXrJQhKHGR99VYzszhJSECqNmeUC5+5Rvo6jn8ol+3C/pjxKTQcukgnONhvUX
      T+diMZL9NmTCm5wgqms3PMr0+bV/MmSQwSyLO98AO1zB9RfvYipZFuHxsbcJO+uV
      dAd1f9/2+zE5SpEtfkHrj+N5WiIvW7ye1YdVGgMHPCIurHKokDTOM9qQw/aPlwpM
      7vYiG4qPatpWTzLItE/nfShKeH58ah+oMgymyKaMEI0AkG91bbXVFQIcKCXWcDn8
      F7Vyf6ss/Ht1Rk2b/Q/uMVHLNUj0P6t3YN7qbnAxf0pKSKQlmTYEi/aYr/ogDmvp
      DW0joxqRAgMBAAECggEATx5XsOLyqLZP0HWd9kXoZZXhcKRDgziXvCtPqvQ2ySz9
      5UnL5nwW5t2EbL5hiXZRgIqo1DGwYlvDoWHFXCmmKayVdYpLaIUH+8+wZHkrSyE/
      NV5CviGpvH9+ZvAwc57oj4Bi3p/6zoRCRnPnT1XBIPdfZdoGQdU8mp/uFljtM7Zx
      Rc2Q0yFWvxI4Hbh07NkpLAWfJVJYDZQGDlq3nQn1BZnPh6Vy9SRIPf9wqWvoTvEF
      HOuhJVG48nhBG7rxayn2ddJx3MmocNaa2vzPJoSn83psUmPM2uWk49RGQl0uQOJW
      jw8ZhgbJox704kgZfvQsxA/bvQ8Z0bhw8f247r7seQKBgQD+fx5F8CrY9Q7KowvE
      QKijIr/fcHt4hD/hSj7hKbo3fmA1c91lYrAMMV9bNXvEdngbCLMCBwAX1q6zepSd
      zcf5Yl90rLkKdP06fTXi+x2vhr667w3a1aQD5CnxldDQal/qfS73yJzspCiq8VEX
      oxNPK8S1SMAQdLJ+C4w7s6JL7wKBgQDLYKu1vP6O02uUCY4/eN+LEdxxC3c28+v5
      +KNddmDI61IvKVjrxytwtS5nmIFUwbb2sExzpV1eDdTOrtmHcngaFP0RL6xicrAS
      RBdTGhehxQCQYfbkyHBoPSAXLGTsgnEEs6AKBKXQ1YrtrKWUENSkn5hIEijmzmnb
      g49CM+SBfwKBgQDUbuWlOYl6mmwjZ6AdzF839Xy2FV1rRvFPrDr6lmszgVDrrXCj
      /ZG4S8ouB2Htp3owDr3ltlQ0keY4ON0vMCN5nszRRpAbE3aBSR0e/8BS0SYKQhuN
      jIGhIeaFGyo3nmO8B4yaFqIuwgSUVGT9Vwl6L62+KSDxW4fWwOrottSFjwKBgFur
      gzozqfnuyfq8I+XwMbKZpmc958pZP/A4ZkpmZVGq4Cxp0q7T43y17ei8EO+HMVUY
      Oh2WV/NhAJ74qQwoSIJZG4h3mJf3Ye2Zy3mltSkxhwONZJ/SyPfzNVe8pvEECrU3
      0dcyKRtsZWaj/y4yN+bMGPPDW7RNLeHH9va8NS85AoGBANaJC2jwz1yaRL4IOzuN
      vrbHL4nAbPDtqfLJCqzxKZEgzEO53BQcsvaVQL26ItyYk7x+cI6Dpp/G2/lqml37
      FWTcFimFMGfBjMGXQpEv7hpeb2f1Ligp1qfOvF0CrxWFgac6yOUk79N5X5PgYwLD
      j/BXCzrX3CVlCkLerKfdW40/
      -----END PRIVATE KEY-----

      """.trimIndent()
  )

  return x509PrivateKeyToBcParameter(serverPk)
}

fun clientPrivateKey(): AsymmetricKeyParameter {
  val clientPk = readPrivateFromString(
    """
      -----BEGIN PRIVATE KEY-----
      MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2t+VvplVqzaja
      FM3NAPeJ44VLB+3T4w3kUBojQwH+0HZMPC+O9DyeKddOr85ScT/pRd9jubRfvzeB
      8XXSRWiymuMgeXLJuz3PLo4CgSaLpOwLZI3EDYYMnIuEaB/RJ8OnObj5DCYH04+y
      oSHqx2nv8LduU0MVgYPjzKvhM+d2isUgY2FV7QxBr+6InwS+uyT6LZl51TebY0yk
      2OqpKk/VZLsUT8QfrbK5O9qs8z6Q33DULwXZhMmefzEoSQwCYvVIfbapkpK5IVKu
      Tvc4h8Ru6yITFobGAOKZ1bBHd0QmZ5ZER9p0KmzocVH2/MIkKvqpAZxU2gX9icSx
      rAz6h3vzAgMBAAECggEAJeF8RKh0Xv8iOYxEmnLP3xt3X/XV3a7eC2577MGQoVZw
      oB9+MKH8C0Jba+nQ2ZC3ElK1HIS8m3kWNe9sYNqY+SZZXjsvjBkwmEprkKNb7WmU
      skv3hCTVnLm7xwibSA55Zqr16VQWclrvGLaFRJpxIRiDvvCuIMBIKqsdG0RagV2r
      89ZEm08t9FVGsXujx8DRW3nLV5w4lHvtiIOPlw4AsENQ7ccv/j1oJWrtRS6uVAVZ
      QfqGc4vtQR3byYOksCvwg6gdbprA8cVCUmWNLRuEfsWWW+8MrxRoNSPUvO94SDGH
      5U46q1LyktmpRhP3kWjf3bsQxiGH4aqfZGy5Do9SmQKBgQDjfQYvdKgUpZ5jh3sF
      5kKIQyhu5s4xAIk5dvDAbOimBp6S8ZVu+zdFUK/ZrJuPZMzLs6W26l5LeIBKrCVT
      KzzBNE3v92mF6S2AOlnOCufaSvBfleRtGywvwTztdIm1wJfAI8C3ecEfLj8fTXrG
      kLCdcfRkd/4+utzAbXpYteh6DwKBgQDNnmxkQFkMHlDUyt7mCu+1G/OSXV/98X6Z
      UqCVgevdIIcD4fxzrTAo9dtodUr5twQ1CFkQ3ml1l/J8Tko69q2ayqyGObjDUgfU
      foyKtV1pVZZ2t6c+zTI0KgKiSfvVgxOIS7XYZJc0G00LdTL3zPlZ1LzeTiDLcIbS
      4b60hskT3QKBgQCATcyGSXJfKsX5drkhK6xMtCwC2LRkmNvMiFPjA8n3kfYwBId2
      r8ONmaOEzsByELUdEradQvRp9o3ND+iBTvqWMYzfkhh3CXu7Pa3W8vmveeK21pCe
      JNw4FvHpL3hYBUbRfJi+IrKUhn3dhtJ/Wa3zLwla/P5tnPDSqyx9CiQTawKBgH2u
      Cd61Hji0BwAqCFhf8uimbxjVjijwBUu+H32C7iI5EY2kAeTKxRckP7n3h55e6Wlo
      8tfGunswJv0n9WNZCAAHRbC9c1uftj2CJHFcLf6GW/Owib9vOPJ9gyKjShTVi4jR
      jhL4WRt2XH9WYZLpbLglulO/OXhgDWi0pxY9FIbZAoGBANvwxkjl1Ic5KzXeAeiE
      TFgwpFCdkUOXhAYj9nRwB0GXJ+fLg1hNwruJqobqnfKZCJ3WBkHNZLzjPmmVkYPK
      5aQCrIveCuqJcQ6kXxkKb+riyXkkIlX+Tkeo2iGClIK32fMr2GUnopx67GrTYyk0
      Hdz9HF3DeNe5yNJyPh4YDyDp
      -----END PRIVATE KEY-----

      """.trimIndent()
  )
  return x509PrivateKeyToBcParameter(clientPk)
}

fun serverCertificate(crypto: BcTlsCrypto): Certificate {
  val serverX509 = readX509FromString(
    """
      -----BEGIN CERTIFICATE-----
      MIIDuzCCAqMCAQEwDQYJKoZIhvcNAQELBQAwgZ4xCzAJBgNVBAYTAmNuMRIwEAYD
      VQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwORXJp
      Y3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRUwEwYDVQQDDAxlcmljc3Nv
      bi5jb20xJDAiBgkqhkiG9w0BCQEWFWdhbHVkaXN1QGVyaWNzc29uLmNvbTAgFw0y
      MTA4MDUwODIzNDlaGA8zMDIwMTIwNjA4MjM0OVowgaUxCzAJBgNVBAYTAmNuMRIw
      EAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwO
      RXJpY3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRwwGgYDVQQDDBNzZXJ2
      ZXIuZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmljc3Nv
      bi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKLudgZKeTUzIe
      HsTYXrJQhKHGR99VYzszhJSECqNmeUC5+5Rvo6jn8ol+3C/pjxKTQcukgnONhvUX
      T+diMZL9NmTCm5wgqms3PMr0+bV/MmSQwSyLO98AO1zB9RfvYipZFuHxsbcJO+uV
      dAd1f9/2+zE5SpEtfkHrj+N5WiIvW7ye1YdVGgMHPCIurHKokDTOM9qQw/aPlwpM
      7vYiG4qPatpWTzLItE/nfShKeH58ah+oMgymyKaMEI0AkG91bbXVFQIcKCXWcDn8
      F7Vyf6ss/Ht1Rk2b/Q/uMVHLNUj0P6t3YN7qbnAxf0pKSKQlmTYEi/aYr/ogDmvp
      DW0joxqRAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACu+nybtFlbQO/sVwvfSm6tg
      miEflTH8gVeR69uI903ldnDuiHKTwY8cV6p12HnDM0s/xjtQ8FN+tKg5a6Q1qqSx
      TWibYqQ2UIo7m6uYhNtMHpzip1O8PMGCg43XQ+/PYdivucgVor8+uSyMomBaPnml
      ZtI0bmi50Gdgrbal+N+jylq7SX7/F/VllAVuO0HxHdPwLLfZ0m9XUpcR3iorm+Be
      yoaWPvccSCsXYIM4bO5HstY/RHDp3/TbeGeeQ2uzKe+nhP9KrFuCx+uTzHzqWW+4
      ZlyTBWPMhdVtQYZx78BmqQ+X8nzJQNZeaD9fRjSa2Un0nJ9j0RLSajlsHVR58/4=
      -----END CERTIFICATE-----

      """.trimIndent()
  )

  return x509CertsToBcCert(crypto, serverX509)

}



fun clientCertificate(crypto: BcTlsCrypto): Certificate {
  val clientX509 = readX509FromString(
    """
      -----BEGIN CERTIFICATE-----
      MIIDuzCCAqMCAQEwDQYJKoZIhvcNAQELBQAwgZ4xCzAJBgNVBAYTAmNuMRIwEAYD
      VQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwORXJp
      Y3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRUwEwYDVQQDDAxlcmljc3Nv
      bi5jb20xJDAiBgkqhkiG9w0BCQEWFWdhbHVkaXN1QGVyaWNzc29uLmNvbTAgFw0y
      MTA4MDUwODIzNTBaGA8zMDIwMTIwNjA4MjM1MFowgaUxCzAJBgNVBAYTAmNuMRIw
      EAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwO
      RXJpY3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRwwGgYDVQQDDBNjbGll
      bnQuZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmljc3Nv
      bi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2t+VvplVqzaja
      FM3NAPeJ44VLB+3T4w3kUBojQwH+0HZMPC+O9DyeKddOr85ScT/pRd9jubRfvzeB
      8XXSRWiymuMgeXLJuz3PLo4CgSaLpOwLZI3EDYYMnIuEaB/RJ8OnObj5DCYH04+y
      oSHqx2nv8LduU0MVgYPjzKvhM+d2isUgY2FV7QxBr+6InwS+uyT6LZl51TebY0yk
      2OqpKk/VZLsUT8QfrbK5O9qs8z6Q33DULwXZhMmefzEoSQwCYvVIfbapkpK5IVKu
      Tvc4h8Ru6yITFobGAOKZ1bBHd0QmZ5ZER9p0KmzocVH2/MIkKvqpAZxU2gX9icSx
      rAz6h3vzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFwi95ttACiCEzrEUpXfKkwT
      ZYkoKTyMf4ZDZ1GsnQ0aX+uJrzDPpcDQzqdH+aWMAZQ50iCCLpOPJ/9ppYbTt/ae
      HRq+2AaS0o9oejx00Z5HCsLiI/flvHxi0px7BnoJnNFVSmz0qBkReR1v19ZwtmQr
      ckZ0weZzOw+PHIfICO5asYvQgnbEzc97bfTsa1wGJIig8IM/0Aw0UNyyrg+IlSwb
      tyaeOISSJHLsm0HAJYvGx8dg4jkM1Tseb7ZnniwGOYh+OEf9Zw3SX7W4sBvxxJoW
      auapIsvzFRgCKRIem7Ji42xJ4mcGHSoejmJoLukv/qrs9/WUiaGvKWFIGf6tiwY=
      -----END CERTIFICATE-----

      """.trimIndent()
  )

  return x509CertsToBcCert(crypto, clientX509)
}


fun iSameCaChain(certificate: Certificate, trustedCAChain: Certificate): Boolean {
  for (clientCA in certificate.certificateEntryList) {
    for (trustedCA in trustedCAChain.certificateEntryList) {
      if (areSameCertificate(
          clientCA.certificate,
          trustedCA.certificate
        )
      ) {
        return true
      }
    }
  }
  return false
}

private fun areSameCertificate(a: TlsCertificate, b: TlsCertificate): Boolean {
  return Arrays.areEqual(a.encoded, b.encoded)
}

private fun x509PrivateKeyToBcParameter(key: PrivateKey): AsymmetricKeyParameter {
  return when (key) {
    is RSAPrivateCrtKey -> {
      RSAPrivateCrtKeyParameters(
        key.modulus,
        key.publicExponent,
        key.privateExponent,
        key.primeP,
        key.primeQ,
        key.primeExponentP,
        key.primeExponentQ,
        key.crtCoefficient
      )
    }
    is RSAPrivateKey -> {
      RSAKeyParameters(true, key.modulus, key.privateExponent)
    }
    is ECPrivateKey -> {
      ECUtil.generatePrivateKeyParameter(key)
    }
    is DSAPrivateKey -> {
      DSAUtil.generatePrivateKeyParameter(key)
    }
    else -> {
      throw InvalidKeyException("unknown key " + key.javaClass.name)
    }
  }
}


fun x509CertsToBcCert(
  crypto: BcTlsCrypto?, x509Certificates: Array<X509Certificate>
): Certificate {
  val bcTlsCertificates: MutableList<BcTlsCertificate> = ArrayList(x509Certificates.size)
  for (x509Certificate in x509Certificates) {
    val bcTlsCertificate = BcTlsCertificate(crypto, x509Certificate.encoded)
    bcTlsCertificates.add(bcTlsCertificate)
  }
  return Certificate(bcTlsCertificates.toTypedArray<TlsCertificate>())
}

fun bcCertToAns1Certs(certificate: Certificate): Array<org.bouncycastle.asn1.x509.Certificate> {
  val asn1x509Certificates: MutableList<org.bouncycastle.asn1.x509.Certificate> =
    ArrayList(certificate.certificateList.size)
  for (tlsCertificate in certificate.certificateList) {
    val x509Certificate = org.bouncycastle.asn1.x509.Certificate.getInstance(tlsCertificate.encoded)
    asn1x509Certificates.add(x509Certificate)
  }
  return asn1x509Certificates.toTypedArray()

}

private fun readX509FromString(data: String): Array<X509Certificate> {
  val x509Certificates = mutableListOf<X509Certificate>()
  PemReader(StringReader(data)).use { reader ->
    val pemObject = reader.readPemObject()
    val content = pemObject.content
    val x509 = CertificateFactory.getInstance("X.509")
      .generateCertificate(ByteArrayInputStream(content)) as X509Certificate
    x509Certificates.add(x509)
  }
  return x509Certificates.toTypedArray()
}

private fun readPrivateFromString(data: String): PrivateKey {
  // Read in the key into a String

  // Read in the key into a String
  val pkcs8Lines = StringBuilder()
  val rdr = BufferedReader(StringReader(data))
  var line: String?
  while (rdr.readLine().also { line = it } != null) {
    pkcs8Lines.append(line)
  }

  // Remove the "BEGIN" and "END" lines, as well as any whitespace


  // Remove the "BEGIN" and "END" lines, as well as any whitespace
  var pkcs8Pem = pkcs8Lines.toString()
  pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "")
  pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "")
  pkcs8Pem = pkcs8Pem.replace("\\s+".toRegex(), "")

  // Base64 decode the result

  // Base64 decode the result
  val pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem)
  // extract the private key
  // extract the private key
  val keySpec = PKCS8EncodedKeySpec(pkcs8EncodedBytes)
  val kf = KeyFactory.getInstance("RSA")
  return kf.generatePrivate(keySpec)

}
