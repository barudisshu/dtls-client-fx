package com.cplier.dtls

import com.cplier.dtls.initializer.DtlsClientInitializer
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.PooledByteBufAllocator
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelOption
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.util.CharsetUtil
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

fun main() {
  val group = NioEventLoopGroup()
  val bootstrap = Bootstrap()
  try {
    val address = InetSocketAddress("127.0.0.1", 4740)
    val channelFuture =
      bootstrap
        .channel(NioDatagramChannel::class.java)
        .group(group)
        .option(ChannelOption.SO_RCVBUF, 20 * 1024 * 1024)
        .option(ChannelOption.SO_SNDBUF, 1024 * 1024)
        .option(ChannelOption.SO_REUSEADDR, true)
        .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
        .handler(DtlsClientInitializer(address))
        .remoteAddress(address)
        .bind(0)
        .sync()

    val ch = channelFuture.channel()
    sendMessage(ch)

    channelFuture.channel().closeFuture().sync()
  } catch (e: InterruptedException) {
    Thread.currentThread().interrupt()
  } finally {
    group.shutdownGracefully()
  }
}

private val scheduler = Executors.newScheduledThreadPool(20)


fun sendMessage(ch: Channel) {
  scheduler.scheduleAtFixedRate(
    {
      val packet = DatagramPacket(
        Unpooled.copiedBuffer("ping", CharsetUtil.UTF_8),
        InetSocketAddress("255.255.255.255", 5244)
      )
      ch.writeAndFlush(packet)
    },
    10,
    5,
    TimeUnit.SECONDS
  )
}
