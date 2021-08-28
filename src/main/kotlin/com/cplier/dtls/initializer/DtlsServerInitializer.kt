package com.cplier.dtls.initializer

import com.cplier.dtls.server.DtlsServer
import com.cplier.dtls.server.DtlsServerHandler
import com.cplier.dtls.server.ReceiverHandler
import io.netty.channel.ChannelInitializer
import io.netty.channel.socket.DatagramChannel

class DtlsServerInitializer : ChannelInitializer<DatagramChannel>() {

  override fun initChannel(ch: DatagramChannel?) {
    ch?.pipeline()?.let {
      it.addLast(DtlsServerHandler(DtlsServer()))
      it.addLast(ReceiverHandler())
    }
  }
}
