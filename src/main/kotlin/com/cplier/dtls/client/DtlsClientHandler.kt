package com.cplier.dtls.client

import com.cplier.dtls.common.DtlsHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.DatagramPacket
import org.bouncycastle.tls.DTLSClientProtocol
import org.bouncycastle.tls.DTLSTransport
import java.net.InetSocketAddress
import java.net.SocketAddress

class DtlsClientHandler(private val mclient: DtlsClient) : DtlsHandler() {

  override fun dtlsTransport(): DTLSTransport {
    val clientProtocol = DTLSClientProtocol()
    rawTransport.setRmoteAddress(mclient.remoteAddress)
    return clientProtocol.connect(mclient, rawTransport)
  }

  override fun connect(
    ctx: ChannelHandlerContext?,
    remoteAddress: SocketAddress?,
    localAddress: SocketAddress?,
    promise: ChannelPromise?
  ) {
    rawTransport.setRmoteAddress(remoteAddress as InetSocketAddress)
    super.connect(ctx, remoteAddress, localAddress, promise)
  }

  override fun channelRead(ctx: ChannelHandlerContext?, msg: Any?) {
    if (msg is DatagramPacket) {
      rawTransport.setRmoteAddress(msg.sender())
    }
    super.channelRead(ctx, msg)
  }
}
