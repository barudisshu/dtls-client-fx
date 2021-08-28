package com.cplier.app

import com.cplier.dtls.*
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.io.File

object DtlsClientCertModifier {
  var rootPath: String? = null
  var pubPath: String? = null
  var priPath: String? = null

  fun getRoot(crypto: BcTlsCrypto): Certificate = rootPath?.let {
    File(it).loadCertificate(crypto)
  } ?: kotlin.run {
    rootCertificate(crypto)
  }

  fun getPub(crypto: BcTlsCrypto): Certificate = pubPath?.let {
    File(it).loadCertificate(crypto)
  } ?: kotlin.run {
    clientCertificate(crypto)
  }

  fun getPri(): AsymmetricKeyParameter = priPath?.let {
    File(it).loadPrivateKey()
  } ?: run {
    clientPrivateKey()
  }
}
