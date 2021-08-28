@file:JvmName("NettyTlsUtils")

package com.cplier.dtls

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import java.io.File
import java.io.FileInputStream
import java.io.FileReader
import java.io.InputStreamReader


/**
 * Pem format file reader
 */
fun File.loadPemResource(): List<PemObject> {
  val pemObjects = mutableListOf<PemObject>()
  PemReader(InputStreamReader(FileInputStream(this))).use { pemReader ->
    var hasNext = true
    while (hasNext) {
      pemReader.readPemObject()?.let { pemObject ->
        pemObjects.add(pemObject)
      } ?: run {
        hasNext = false
      }
    }
  }
  return pemObjects
}

fun File.loadCertificate(crypto: BcTlsCrypto): Certificate {
  val pemObjects = this.loadPemResource()
  val tlsCertificates = mutableListOf<TlsCertificate>()
  pemObjects.forEach { pemObject ->
    if (pemObject.type.endsWith("CERTIFICATE")) {
      val certificate = crypto.createCertificate(pemObject.content)
      tlsCertificates.add(certificate)
    }
  }
  return Certificate(tlsCertificates.toTypedArray())
}

fun File.loadPrivateKey(): AsymmetricKeyParameter? {
  PEMParser(FileReader(this)).use { parser ->
    parser.readObject()?.let { pemObject ->
      return when (pemObject) {
        is PrivateKeyInfo -> PrivateKeyFactory.createKey(pemObject)
        is PEMKeyPair -> PrivateKeyFactory.createKey(pemObject.privateKeyInfo.encoded)
        else -> throw IllegalArgumentException("unexpected private key")
      }
    } ?: run {
      return null
    }
  }
}
