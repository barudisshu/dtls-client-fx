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
      MIIEFjCCAv6gAwIBAgIJAPgW2xTIi9DpMA0GCSqGSIb3DQEBCwUAMIGeMQswCQYD
      VQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3pob3Ux
      FzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEVMBMG
      A1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmlj
      c3Nvbi5jb20wIBcNMjEwNzEwMDMyNDM0WhgPMzAyMDExMTAwMzI0MzRaMIGeMQsw
      CQYDVQQGEwJjbjESMBAGA1UECAwJR3Vhbmdkb25nMRIwEAYDVQQHDAlHdWFuZ3po
      b3UxFzAVBgNVBAoMDkVyaWNzc29uLCBJbmMuMREwDwYDVQQLDAhlcmljc3NvbjEV
      MBMGA1UEAwwMZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBl
      cmljc3Nvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCaHRGS
      oBgQyNfGAqAtR4TOCgdoB5DHrWFdGcwAOZ1Z7GK24W8NzQPVde9ZmxEAj4fOoYPw
      Twi6nS7qqth+Z1f9WKrDWJ+pzWP2Dl1oPnjHVPV/bT5KgfRrRBaj30lhzw7HZVHA
      3ezEgjS1WRATsEol0SpCsXthOhR0mwBZYm50GRYJNnSt2+pW3/p549v5ZzZkhH65
      W1aecL0RJzYAsSIp0lu7WW3iGUxcxWME+g5tzgdMrR7qhTa+f8FDk7kDHnRq/Y/V
      +7N2Eglop/c4guoMiUeMUngNA/KGTloFnwc+TegKkS9JHH3Z17cPtY9b5N7r7E1O
      2WsnvSUnT/2o6GIdAgMBAAGjUzBRMB0GA1UdDgQWBBSCjPSKgr7NgFE8bkJkhZNC
      QsNMHDAfBgNVHSMEGDAWgBSCjPSKgr7NgFE8bkJkhZNCQsNMHDAPBgNVHRMBAf8E
      BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCD6H4zcvKW/UZo70JcdM0D8btFtZBg
      rturB8100JY5aDgHq1O+aCswi0ypgH4l14YwN4HEWOz0UdAktVzwPdYBsu3/YBXu
      zOa5eawlAzSRfYFU946P70xJX1ABSRnNuE3seDPvxH3Fe76y6JrAVsNWYuuMkqY4
      HUSzlRQJAz4+lM+kc7LWNH1dy0tmUkOHaT3TVxpqcfVA8HEiC2lD5sUFo+W1Tl9o
      jnl5pcR3DL3JdVWB0BDVxFK2enmeVowZUGL/ZQu//YJuG6mVQs+FA4JHp5IiO9iX
      kFZiQuJ1nn8OQvfyU6WvE5InIq0JDtawR3osa4b+MvZmoe6i6pgq56rP
      -----END CERTIFICATE-----
      """.trimIndent()
  )

  return x509CertsToBcCert(crypto, rootX509)
}

fun serverPrivateKey(): AsymmetricKeyParameter {
  val serverPk = readPrivateFromString(
    """
      -----BEGIN PRIVATE KEY-----
      MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDL4WPoe32kpGXX
      K6o07LT+67MQXtZRiImm0F6XnqSafNIVQ8bLjyHgQYQP8PAGIRw3PMCB7lA1oyDI
      uGckB5FKeYM3X7Ig60xkWS1qRB4nZozb7JjMacT5E79/Bk4bYR6kesHfBZWq4yYS
      vb8Lle4b1Kldx9WvD9X07g+idFEOdk5Dh8h83HHpE1ODHsrvDuSEsVrVWmVE1YJ3
      ++vyyocnClX8v+WJEtp8jEdEPMgoSFLWaENd5OMQnr/gzdyPFOfzf1PUZTuwGO6y
      SVIvDi1JQYkiWaYkYeEHhjcZr2H4QzfoZMBMnajRqRs52hUbEq55lPpor6pIkcnN
      ie/ZiQKXAgMBAAECggEAO7OhpPdcgHTfmZWgvuS9z5RHmDidO7zmyiFkQbPj8ZUx
      k6aINR2RxvCIcn6UWschUw+IM8QMWtiNBhnxofxRUGSqxvFP4RHmCdCPWvnddp4y
      C0iKKfmjA2kD/3diMeRLq9CCqwMgo6zmfkBwDD14P1AT1HFrIltZxOJdU64J+lim
      GXsWCJ4r3YZsJHIqqEGDZYUUcLE78kzTKSBh8ByYo1qdM8Ajq8m7jGKrd6ViVhKa
      KT+Tvy0uEmWOFZ0PqxR6UK9w2DaDbv5ZPB9SIWuY4vzcjcGgl8WnkQByZc+jJ1en
      MLZqJPXEt6X6RQAWjyjXryIwLCtvQ2v799sDKZdH6QKBgQD5l+hP14IydqO2Ftp/
      1Pa2pw7FHablw2oQ9B1kj7ocWiHN7fStU7/IRe3FdaC2dzGzDlgsxqs2U91ces62
      Vp336xgExskpyHsy6gpp5IdGa+koX1rj5XxaCO6U21b7kCdvLCatmWPFiNyBADif
      h8PxED1rQwIsa1SYo48ImsBmswKBgQDRHRmug94QLPI9l9RpsoKiOf32JwmmYiDJ
      +Hac1JcY1E71cAIXzrKa0o5XaN7fvgPn1KHZl5K2kwHrNN1zIn4K190yblfzCyRy
      a+pAQXyBlSsHjTiKjC7PfISQ8EuASSZhyfKPPy+si+bDMPfyGN8aXK85DHibljPS
      jGZaelbGjQKBgQC2aaAeYhnEedKyLMep72IUIcn4o/ArMgNdupuUuDpDqFfWYheV
      aYTbgMgCrTI0yK4o983Xg6bzwJ0ijppuxqUS4N2f+AxjHiN0FXpg4+U9wXYYzH/n
      2Ptl7es4HYnXtwYrCPCHpXg2kQzetuOrLBU3JDBPKRz4i8S6/aZ2mmsNYwKBgQCW
      C8xutX40mxuiaHxo70bfAr+gzXgWJBkk8xyhAcX9cfHKGPnXfWAYyXaLb9tkLiL9
      SUxtJl6GlMtuqvsvbxOD0kqMsjJ3WYpoc9idDKA7Fv7OJ13nxBieltlEareyMErT
      JiXe9VbO93+4lT2EQKZtcw3j4Hf2I/vBWy7iQyBazQKBgQDXeeLYuX2NGaYdkSF5
      CPzPeTBPA4GUQouo+6dxgCytgtmJJhVdUNNFeRL3msmPVl0Zl42Ji50jFHXHCcBg
      k30K7Q55A/GRtQDg8ml9dHD+yWdoDh1lDxeMkylG4CrARa1nVHj21WAp5V/r6TQY
      dHUDstgTMC11fXQPUWc/pwQdng==
      -----END PRIVATE KEY-----
      """.trimIndent()
  )

  return x509PrivateKeyToBcParameter(serverPk)
}

fun clientPrivateKey(): AsymmetricKeyParameter {
  val clientPk = readPrivateFromString(
    """
      -----BEGIN PRIVATE KEY-----
      MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDAtY5h0kIsEW+s
      a5l+hWaxinyRPkZalCSsuFFMQCFaUnyLZYEjUdLJvr//tsu/R6igyzIyqWX1XAIa
      VSayBpskMcyngvwtcPrXV4v5YlxqkzeHM67BjliBdJYLtRPEvyiREFyDsvH8JTI3
      Ejn0ZSazI/lXpavSKntUkTMmK7pAUi5b29RWTLY1UAWkuMplAYJe9qAdGbAaDRoP
      Ak+1M4HajvCJQLDIIQY+3DnboDg0FrVcRC9y7YMbD1pU6WiX0dl2DpZOh6leCMFW
      aVen5hL678zsdFD5ri8LMVpArQo7ukObRfE93CorIXrgUJ7U2gbM/e6k5Kfm1ER4
      NfdswzhdAgMBAAECggEBAIUpb9e8mKkm60nzmD9LIykvjuA2bhsNH0KSourTrbhi
      I1mXrGKhmcx6mOW0hJoKhEWH44oKcD/ZckKL8I837WBXYRmnc2ZbGZpQDpMnGsEy
      NT6hwfJR0Gq0CzLPz3c2uGt1KNiAgKJBea+AUrfEZbeH9jZQbqhtXoeTRgrsUGk8
      qu6cZ40EvvV156ZcArFCrD33SHo+aBd34lH3FmOKX07zY6dLWcARbJ5q2SFWSO+V
      6QWytrKFW3U1eWflk6vy/vGFSrjr8lsA8QyjkE5zTqp75FesKE8J/bnS008TRnrG
      yfSfeCejiUCm9DoWVUDh1XOEHYB3QjgGhT56+Hs90ykCgYEA/M2WlQl0p0BBT3zS
      4AsfwLVpoVv7fkX6KfeVO9vdB1v7aO7HqWv9N2tMNQ54h73yZOLD26T5OR7OEHLM
      QWKiu9989aHIpCj79KHe+v4N6On1ajzHgA6gbVeksay6RqGMJ4Ex8NPzcmEniQiJ
      nMgMvanMsLXv9Ih5DxIqGCQhPvcCgYEAwyVsUdKRmZymzcii5jeeAL7pC6JtvcBP
      tVjHFPzBRPndCZKKqPs67LV4Ht8uE1rpk59pWftbyJX82bK5pvS/cSLRR1KoJChP
      7C7scmHOJBYv25sELVN2VQTBu8DaJG0HRREJYYZ7GhqtRjaNP/FskqzD6Gxm7ow+
      KvUk67JI6ksCgYEAtc+xtXv4bnSyw9T03/aAHpsZ3deGVrlDAj2yETu9iZZoiH36
      EGm+0cWUKDBBFPbRxiakT2olZyQ1dPTq2zdx7AX+G7X/07g6BCUKdZ6TKGhifMY7
      gGiEjj7TDok36qYyYxLydM4qLp+azF3cgmoJZ7ofoRMoAMjJr8ITjgsl8d8CgYEA
      iK+dv3IOKdpfu6Pc9gPe2AbglRWgaFhbfFpCl6Cyfu3EtP+/v7y4+TPifz0zuLrl
      AFGYKT62ezkTciiNgTPNJCGPFLYAr9LMqFH1q+h1yzD/NILP2i+rosFCMZBTO1Bi
      1y2ntHfNoestkxCCv1cLBXGdhx7mug/hO5WZ1r159SECgYEA8eGl4rUAAbIUE7qg
      3Ekd2ouzkiXRKRjJlzz5pXsU4VpazzZuewHb+F/DyH0H/SK11gY0iB/EtW9VH3mH
      l0qltvIzQv26OKjnZfJlI8Y/q60JJgGxtbT5Zm3A2OVI5oVBHeD1ElZNIVEyFuCA
      5MPzUvSLQaNfqXGaXGwNdZWxADE=
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
      MTA3MTAwMzI0NDZaGA8zMDIwMTExMDAzMjQ0NlowgaUxCzAJBgNVBAYTAmNuMRIw
      EAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwO
      RXJpY3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRwwGgYDVQQDDBNzZXJ2
      ZXIuZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmljc3Nv
      bi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL4WPoe32kpGXX
      K6o07LT+67MQXtZRiImm0F6XnqSafNIVQ8bLjyHgQYQP8PAGIRw3PMCB7lA1oyDI
      uGckB5FKeYM3X7Ig60xkWS1qRB4nZozb7JjMacT5E79/Bk4bYR6kesHfBZWq4yYS
      vb8Lle4b1Kldx9WvD9X07g+idFEOdk5Dh8h83HHpE1ODHsrvDuSEsVrVWmVE1YJ3
      ++vyyocnClX8v+WJEtp8jEdEPMgoSFLWaENd5OMQnr/gzdyPFOfzf1PUZTuwGO6y
      SVIvDi1JQYkiWaYkYeEHhjcZr2H4QzfoZMBMnajRqRs52hUbEq55lPpor6pIkcnN
      ie/ZiQKXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFzPz38pAUAwYwSyE8KJng1X
      dmeEx9JKCNZ/JXmkRcfk+L6fQxLIWeSeNeGYUKpR/JblXHuq4ztJb4rmJaABxmMJ
      otujfQWku+xp4c566/dYDnOVZhH8T+WC3FyCtMPTVJkYJFtBzt4gs9742VFwm9j1
      EnDz13tflUYbEKU/fq7wUNSpB+Q8W+nFVeJQU8jPyi6jisn/25T0VgjRQRgs6VK9
      z9lbaLVh/DVtnGRcMkoK+UsMu0eGl9Mn1VVyPZz71835oZJoUWt0aimb/W9yG7rL
      SqQ9x9dgGCjzMLERO8lb0KWY5FnLHmztEAxU97/ME5ZMn3S06aAiNQa3l53UzFo=
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
      MTA3MTAwMzI0NDZaGA8zMDIwMTExMDAzMjQ0NlowgaUxCzAJBgNVBAYTAmNuMRIw
      EAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwO
      RXJpY3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRwwGgYDVQQDDBNjbGll
      bnQuZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmljc3Nv
      bi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDAtY5h0kIsEW+s
      a5l+hWaxinyRPkZalCSsuFFMQCFaUnyLZYEjUdLJvr//tsu/R6igyzIyqWX1XAIa
      VSayBpskMcyngvwtcPrXV4v5YlxqkzeHM67BjliBdJYLtRPEvyiREFyDsvH8JTI3
      Ejn0ZSazI/lXpavSKntUkTMmK7pAUi5b29RWTLY1UAWkuMplAYJe9qAdGbAaDRoP
      Ak+1M4HajvCJQLDIIQY+3DnboDg0FrVcRC9y7YMbD1pU6WiX0dl2DpZOh6leCMFW
      aVen5hL678zsdFD5ri8LMVpArQo7ukObRfE93CorIXrgUJ7U2gbM/e6k5Kfm1ER4
      NfdswzhdAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABOt2EqEZbgHjLvq23ByqfSt
      DVhyyMFAs5DgyECHE73aDZxk8iJ4lRmhBwmNAYHwkf+PmBnUdWkF2uIxrZzoHGpQ
      u4fj6sHLO5JV5TzBqzS87c7v2RnvtsWoAjcgKZQ9/axTSfekAp7/2WE3LSLeAMUN
      wbA/Gd2E8Zky5CL/D2rSRMySl2E/o1+jLudv7HFq8pvmoA9K3m6JYIFoE2byrZ+f
      ozmYviOKSz88bFHPXeUXKG3FIhTlrkMMWP6kyjTdx3iFYpKI+bCw7tUsSoCkDA/C
      JdeRcYCbRRVdPStE7w5p7FCS946C4A6Rx31N0jNWTN7ofPhVR8F+lt0hrvcWj2I=
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
  val pkcs8Lines = StringBuilder()
  val rdr = BufferedReader(StringReader(data))
  var line: String?
  while (rdr.readLine().also { line = it } != null) {
    pkcs8Lines.append(line)
  }

  // Remove the "BEGIN" and "END" lines, as well as any whitespace
  var pkcs8Pem = pkcs8Lines.toString()
  pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "")
  pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "")
  pkcs8Pem = pkcs8Pem.replace("\\s+".toRegex(), "")

  // Base64 decode the result
  val pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem)
  // extract the private key
  val keySpec = PKCS8EncodedKeySpec(pkcs8EncodedBytes)
  val kf = KeyFactory.getInstance("RSA")
  return kf.generatePrivate(keySpec)

}
