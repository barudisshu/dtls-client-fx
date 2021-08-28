package com.cplier.dtls.server

import com.cplier.dtls.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.SecureRandom
import java.util.*

class DtlsServer : DefaultTlsServer(BcTlsCrypto(SecureRandom())) {

  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(DtlsServer::class.java)
  }

  override fun getSupportedVersions(): Array<ProtocolVersion> {
    return ProtocolVersion.DTLSv12.downTo(ProtocolVersion.DTLSv10)
  }

  override fun getHeartbeatPolicy(): Short {
    return HeartbeatMode.peer_allowed_to_send
  }

  override fun getHeartbeat(): TlsHeartbeat {
    return DefaultTlsHeartbeat(10_000, 10_000)
  }

  override fun getRenegotiationPolicy(): Int {
    return RenegotiationPolicy.ACCEPT
  }

  override fun notifyAlertReceived(alertLevel: Short, alertDescription: Short) {
    LOGGER.trace("notify alert to peer client")
    super.notifyAlertReceived(alertLevel, alertDescription)
  }

  override fun notifyClientCertificate(certificate: Certificate?) {
    if (certificate == null || certificate.isEmpty) {
      throw TlsFatalAlert(AlertDescription.bad_certificate)
    }

    val trustedCAChain = rootCertificate(context.crypto as BcTlsCrypto)
    if (!iSameCaChain(certificate, trustedCAChain)) {
      throw TlsFatalAlert(AlertDescription.bad_certificate)
    }
    TlsUtils.checkPeerSigAlgs(context, certificate.certificateList)
  }

  override fun getCertificateRequest(): CertificateRequest {
    var serverSigAlgs: Vector<SignatureAndHashAlgorithm>? = null
    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(ProtocolVersion.DTLSv12)) {
      val hashAlgorithms = shortArrayOf(
        HashAlgorithm.sha512, HashAlgorithm.sha384,
        HashAlgorithm.sha256,
        HashAlgorithm.sha224,
        HashAlgorithm.sha1
      )

      val signatureAlgorithms = shortArrayOf(SignatureAlgorithm.rsa)
      serverSigAlgs = Vector()
      for (hashAlgorithm in hashAlgorithms) {
        for (signatureAlgorithm in signatureAlgorithms) {
          serverSigAlgs.addElement(SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm))
        }
      }
    }

    val trustedCAChain = rootCertificate(context.crypto as BcTlsCrypto)
    val ans1509 = bcCertToAns1Certs(trustedCAChain)[0]

    val certificateAuthorities: Vector<X500Name> = Vector()
    certificateAuthorities.add(ans1509.subject)

    return CertificateRequest(
      shortArrayOf(ClientCertificateType.rsa_sign),
      serverSigAlgs,
      certificateAuthorities
    )
  }

  override fun getCredentials(): TlsCredentials {
    // extract signature
    val signatureAndHashAlgorithm = extractSignatureFromTlsServerContext(context)
    // loading private key asymmetric parameter
    val asymmetricKeyParameter = serverPrivateKey()
    val serverCert = serverCertificate(context.crypto as BcTlsCrypto)
    val rootCert = rootCertificate(context.crypto as BcTlsCrypto)
    val caChains: Array<TlsCertificate> = rootCert.certificateList
    val certChains: Array<TlsCertificate> = serverCert.certificateList
    if (caChains.isEmpty() || certChains.isEmpty()) {
      throw TlsFatalAlert(AlertDescription.no_certificate)
    }
    TlsUtils.checkPeerSigAlgs(context, certChains)
    val cert = Certificate(arrayOf(certChains[0], caChains[0]))
    return BcDefaultTlsCredentialedSigner(
      TlsCryptoParameters(context),
      context.crypto as BcTlsCrypto,
      asymmetricKeyParameter,
      cert,
      signatureAndHashAlgorithm
    )

  }

  private fun extractSignatureFromTlsServerContext(context: TlsServerContext?): SignatureAndHashAlgorithm? {
    var sigAlgs = context?.securityParametersHandshake?.clientSigAlgs
    if (sigAlgs == null) {
      sigAlgs = TlsUtils.getDefaultSignatureAlgorithms(SignatureAlgorithm.rsa)
    }
    var signatureAndHashAlgorithm: SignatureAndHashAlgorithm? = null
    sigAlgs?.forEach lit@{ sigAlg ->
      val alg = sigAlg as SignatureAndHashAlgorithm
      if (alg.signature.toInt() == KeyExchangeAlgorithm.RSA) {
        signatureAndHashAlgorithm = alg
        return@lit
      }
    }

    return signatureAndHashAlgorithm
  }
}
