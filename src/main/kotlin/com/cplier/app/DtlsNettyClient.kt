package com.cplier.app

import com.cplier.dtls.client.DtlsClient
import com.cplier.dtls.client.DtlsClientHandler
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.PooledByteBufAllocator
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelId
import io.netty.channel.ChannelOption
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.pool.AbstractChannelPoolHandler
import io.netty.channel.pool.AbstractChannelPoolMap
import io.netty.channel.pool.SimpleChannelPool
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.util.CharsetUtil
import org.bouncycastle.util.encoders.Hex
import java.net.InetSocketAddress
import java.util.*
import java.util.concurrent.TimeUnit

object DtlsNettyClient {

  private var poolMap: AbstractChannelPoolMap<InetSocketAddress, SimpleChannelPool>? = null
  private var channelPool: SimpleChannelPool? = null
  private var currentChannel: Channel? = null
  private val connections = mutableMapOf<ChannelId?, DtlsClient>()
  private val group = NioEventLoopGroup()
  private val bootstrap = Bootstrap()

  init {
    bootstrap.channel(NioDatagramChannel::class.java)
      .group(group)
      .option(ChannelOption.SO_RCVBUF, 20 * 1024 * 1024)
      .option(ChannelOption.SO_SNDBUF, 1024 * 1024)
      .option(ChannelOption.SO_REUSEADDR, true)
      .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)

    val host = System.getenv("HOST").takeUnless { it.isNullOrBlank() } ?: "127.0.0.1"
    val port = System.getenv("PORT").takeUnless { it.isNullOrBlank() } ?: "4740"

    val address = InetSocketAddress(host, port.toInt())

    poolMap = object : AbstractChannelPoolMap<InetSocketAddress, SimpleChannelPool>() {
      override fun newPool(key: InetSocketAddress?): SimpleChannelPool {
        return SimpleChannelPool(bootstrap.remoteAddress(address), object : AbstractChannelPoolHandler() {
          override fun channelCreated(ch: Channel?) {
            val dtlsClient = DtlsClient(address)
            ch?.pipeline()?.addLast(DtlsClientHandler(dtlsClient))
            connections[ch?.id()] = dtlsClient
          }
        })
      }
    }
    channelPool = poolMap?.get(address)
  }


  fun send(data: String) {
    if (currentChannel == null) {
      acquireNewChannel()
    }

    waitForHandshakeFinish()

    if (currentChannel == null) return

    val address = InetSocketAddress("255.255.255.255", 2525)

    val bytes: ByteArray = try {
      Hex.decode(data)
    } catch (e: Exception) {
      data.toByteArray(CharsetUtil.UTF_8)
    }

    val packet = DatagramPacket(Unpooled.copiedBuffer(bytes), address)
    currentChannel?.writeAndFlush(packet)
  }

  private fun acquireNewChannel() {
    channelPool?.let {
      val fc = it.acquire()
      try {
        currentChannel = fc.get()
      } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
      }
    }
  }

  private fun waitForHandshakeFinish() {
    if (currentChannel == null) {
      val timeout = Date().time + 10_000L
      try {
        while (currentChannel == null && Date().time < timeout) {
          TimeUnit.SECONDS.sleep(1)
          if (currentChannel != null) {
            break
          }
        }
      } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
      }
    }
  }
}
