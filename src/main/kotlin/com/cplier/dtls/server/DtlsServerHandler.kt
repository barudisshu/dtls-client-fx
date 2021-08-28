package com.cplier.dtls.server

import com.cplier.dtls.common.DtlsHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.socket.DatagramPacket
import org.bouncycastle.tls.DTLSServerProtocol
import org.bouncycastle.tls.DTLSTransport

class DtlsServerHandler(private val mserver: DtlsServer) : DtlsHandler() {

  override fun channelRead(ctx: ChannelHandlerContext?, msg: Any?) {
    if (msg is DatagramPacket) {
      rawTransport.setRmoteAddress(msg.sender())

    }
    super.channelRead(ctx, msg)
  }

  override fun dtlsTransport(): DTLSTransport {
    val serverProtocol = DTLSServerProtocol()
    return serverProtocol.accept(mserver, rawTransport)
  }
}
