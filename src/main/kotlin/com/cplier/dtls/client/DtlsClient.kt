package com.cplier.dtls.client

import com.cplier.app.DtlsClientCertModifier
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.bouncycastle.util.Arrays
import java.net.InetSocketAddress
import java.security.SecureRandom

class DtlsClient(internal val remoteAddress: InetSocketAddress) : DefaultTlsClient(BcTlsCrypto(SecureRandom())) {

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

  override fun getAuthentication(): TlsAuthentication {
    return object : TlsAuthentication {
      override fun notifyServerCertificate(serverCertificate: TlsServerCertificate?) {
        TlsUtils.checkPeerSigAlgs(context, serverCertificate?.certificate?.certificateList)
      }

      override fun getClientCredentials(certificateRequest: CertificateRequest?): TlsCredentials? {
        val certificateTypes = certificateRequest?.certificateTypes
        if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign)) {
          return null
        }

        var signatureAndHashAlgorithm: SignatureAndHashAlgorithm? = null
        val sigAlgs = certificateRequest.supportedSignatureAlgorithms
        sigAlgs?.forEach lit@{ sigAlg ->
          val alg = sigAlg as SignatureAndHashAlgorithm
          if (alg.signature.toInt() == KeyExchangeAlgorithm.RSA) {
            signatureAndHashAlgorithm = alg
            return@lit
          }
        }
        val rootCert = DtlsClientCertModifier.getRoot(context.crypto as BcTlsCrypto)
        val clientCert = DtlsClientCertModifier.getPub(context.crypto as BcTlsCrypto)
        if (rootCert.isEmpty || clientCert.isEmpty) {
          throw TlsFatalAlert(AlertDescription.no_certificate)
        }
        TlsUtils.checkPeerSigAlgs(context, clientCert.certificateList)
        val certs = Certificate(arrayOf(clientCert.getCertificateAt(0), rootCert.getCertificateAt(0)))
        val privateKey = DtlsClientCertModifier.getPri()
        return BcDefaultTlsCredentialedSigner(
          TlsCryptoParameters(context),
          context.crypto as BcTlsCrypto,
          privateKey,
          certs,
          signatureAndHashAlgorithm
        )

      }
    }
  }
}
