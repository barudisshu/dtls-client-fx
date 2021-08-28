package com.cplier.dtls.server

import io.netty.channel.ChannelHandlerContext
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.DatagramPacket
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class ReceiverHandler : SimpleChannelInboundHandler<DatagramPacket>() {
  private val logger: Logger = LoggerFactory.getLogger(ReceiverHandler::class.java)
  override fun channelRead0(ctx: ChannelHandlerContext?, msg: DatagramPacket?) {
    logger.debug("received datagram packet")
  }
}
