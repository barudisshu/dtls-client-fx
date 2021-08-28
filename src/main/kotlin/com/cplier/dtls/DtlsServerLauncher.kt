package com.cplier.dtls

import com.cplier.dtls.initializer.DtlsServerInitializer
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.PooledByteBufAllocator
import io.netty.channel.ChannelOption
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioDatagramChannel

fun main() {
  val group = NioEventLoopGroup()
  val bootstrap = Bootstrap()
  try {
    val channelFuture =
      bootstrap
        .channel(NioDatagramChannel::class.java)
        .group(group)
        .option(ChannelOption.SO_RCVBUF, 20 * 1024 * 1024)
        .option(ChannelOption.SO_SNDBUF, 1024 * 1024)
        .option(ChannelOption.SO_REUSEADDR, true)
        .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
        .handler(DtlsServerInitializer())
        .bind("127.0.0.1", 4740)
        .sync()
    channelFuture.channel().closeFuture().sync()
  } catch (e: InterruptedException) {
    Thread.currentThread().interrupt()
  } finally {
    group.shutdownGracefully()
  }

}
