package com.cplier.app

import com.cplier.dtls.client.DtlsClient
import com.cplier.dtls.client.DtlsClientHandler
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.PooledByteBufAllocator
import io.netty.buffer.Unpooled
import io.netty.channel.*
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.pool.AbstractChannelPoolHandler
import io.netty.channel.pool.AbstractChannelPoolMap
import io.netty.channel.pool.ChannelHealthChecker
import io.netty.channel.pool.SimpleChannelPool
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.util.CharsetUtil
import io.netty.util.concurrent.Future
import io.netty.util.concurrent.FutureListener
import org.bouncycastle.util.encoders.Hex
import java.net.InetSocketAddress
import java.util.concurrent.BlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

object DtlsNettyClient {

  private var poolMap: AbstractChannelPoolMap<InetSocketAddress, SimpleChannelPool>? = null
  private var channelPool: SimpleChannelPool? = null
  private var currentChannel: Channel? = null
  private val connections = mutableMapOf<ChannelId?, DtlsClient>()

  private val executorService = Executors.newWorkStealingPool()
  private val atomicInit = AtomicBoolean(false)
  private val packetQueue: BlockingQueue<DatagramPacket> = LinkedBlockingQueue()
  private val idleCheck = Executors.newSingleThreadScheduledExecutor()

  private val eventLoopRef = AtomicReference<EventLoopGroup>()
  private val bootstrapRef = AtomicReference<Bootstrap>()


  init {
    val group = NioEventLoopGroup()

    val bootstrap = Bootstrap()
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
        return SimpleChannelPool(
          bootstrap.remoteAddress(address), object : AbstractChannelPoolHandler() {
            override fun channelCreated(ch: Channel?) {
              val dtlsClient = DtlsClient(address)
              ch?.pipeline()?.addLast(DtlsClientHandler(dtlsClient))
              connections[ch?.id()] = dtlsClient
            }
          },
          ChannelHealthChecker.ACTIVE,
          true,
          false
        )
      }
    }

    eventLoopRef.set(group)
    bootstrapRef.set(bootstrap)
    channelPool = poolMap?.get(address)

    idle()

    Runtime.getRuntime().addShutdownHook(Thread(this::close))
  }

  private fun idle() {
    idleCheck.scheduleWithFixedDelay(
      {
        // current channel's handshake finish but still message left should be consumed.
        if (currentChannel != null && atomicInit.get() && !packetQueue.isEmpty() && isHandshakeFinish()) {
          val packetList = mutableListOf<DatagramPacket>()
          packetQueue.drainTo(packetList)
          for (packet in packetList) {
            executorService.submit<ChannelFuture> {
              currentChannel!!.writeAndFlush(
                packet
              ).sync()
            }
          }
        }
      },
      0,
      200,
      TimeUnit.MILLISECONDS
    )
  }

  fun send(data: String) {
    val address = InetSocketAddress("255.255.255.255", 2525)

    val bytes: ByteArray = try {
      Hex.decode(data)
    } catch (e: Exception) {
      data.toByteArray(CharsetUtil.UTF_8)
    }

    val packet = DatagramPacket(Unpooled.copiedBuffer(bytes), address)

    if (currentChannel != null && atomicInit.get()) {
      executorService.submit { currentChannel?.writeAndFlush(packet)?.sync() }
    } else {
      if (atomicInit.compareAndSet(false, true)) {
        channelPool?.acquire()?.addListener(FutureListener { future ->
          if (future.isSuccess) {
            val ch = future.now
            currentChannel = ch
            packetQueue.add(packet)
          }
        })
      } else {
        packetQueue.add(packet)
      }
    }
  }

  fun releaseCurrentConnection() {
    if (currentChannel != null && atomicInit.get()) {
      channelPool
        ?.release(currentChannel)
        ?.addListener { r: Future<in Void?> ->
          if (r.isSuccess) {
            currentChannel!!
              .disconnect()
              .addListener { d: Future<in Void?> ->
                if (d.isSuccess) {
                  currentChannel!!
                    .deregister()
                    .addListener { dr: Future<in Void?> ->
                      if (dr.isSuccess) {
                        currentChannel!!
                          .close()
                          .addListener { c: Future<in Void?> ->
                            if (c.isSuccess) {
                              connections.remove(currentChannel!!.id())
                              atomicInit.compareAndSet(true, false)
                            }
                          }
                      }
                    }
                }
              }
          }
        }
    }
  }


  private fun isHandshakeFinish(): Boolean {
    if (currentChannel != null && atomicInit.get()) {
      val currentClient = connections[currentChannel!!.id()]
      if (currentClient != null) {
        return currentClient.isHandshakeComplete()
      }
    }
    return false
  }

  fun close() {
    releaseCurrentConnection()
    poolMap?.close()
    connections.clear()
    eventLoopRef.get().shutdownGracefully()
    bootstrapRef.get().clone()
    idleCheck.shutdown()
    executorService.shutdown()

  }
}
