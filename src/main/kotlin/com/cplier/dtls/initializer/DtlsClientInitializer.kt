package com.cplier.dtls.initializer

import com.cplier.dtls.client.DtlsClient
import com.cplier.dtls.client.DtlsClientHandler
import io.netty.channel.ChannelInitializer
import io.netty.channel.socket.DatagramChannel
import java.net.InetSocketAddress

class DtlsClientInitializer(private val remoteAddress: InetSocketAddress) : ChannelInitializer<DatagramChannel>() {
  override fun initChannel(ch: DatagramChannel?) {
    ch?.pipeline()?.addLast(DtlsClientHandler(DtlsClient(remoteAddress)))
  }
}
