package com.cplier.dtls.common

import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.DatagramPacket
import org.bouncycastle.tls.DTLSTransport
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.concurrent.BlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue

abstract class DtlsHandler : ChannelDuplexHandler() {

  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(DtlsHandler::class.java)
  }

  internal class ChannelContext(val ctx: ChannelHandlerContext?, val promise: ChannelPromise?)

  private val writeCtxQueue: BlockingQueue<ChannelContext> = LinkedBlockingQueue()
  protected val rawTransport = DtlsHandlerTransport()
  private val engine: DtlsEngine = DtlsEngine(rawTransport)

  private var executor = Executors.newSingleThreadExecutor()

  override fun channelActive(ctx: ChannelHandlerContext?) {
    LOGGER.trace("channelActive")
    super.channelActive(ctx)
    rawTransport.setChannel(ctx?.channel())
    executor.execute { doHandshake() }
  }

  private fun doHandshake() {
    try {
      LOGGER.trace("${name()} init start")
      val encTransport: DTLSTransport = dtlsTransport()
      LOGGER.trace("handshake finish")
      engine.initialize(encTransport)
      LOGGER.trace("${name()} init end")
    } catch (e: IOException) {
      LOGGER.error("handshake fail", e)
    }
  }

  override fun channelRead(ctx: ChannelHandlerContext?, msg: Any?) {
    if (msg is DatagramPacket) {
      LOGGER.trace("${name()} channelRead")
      // send packet to underlying transport for consumption
      val packets = engine.read(msg)
      for (packet in packets) {
        super.channelRead(ctx, packet)
      }
    } else
      super.channelRead(ctx, msg)
  }

  override fun write(ctx: ChannelHandlerContext?, msg: Any?, promise: ChannelPromise?) {
    when (msg) {
      is DatagramPacket -> {
        // this is the un-encrypted data written by the app
        LOGGER.trace("${name()} write $msg")
        // flush the queue when channel initialized
        if (engine.isInitialized()) {
          // assume messages are one-to-one between raw and encrypted
          writeCtxQueue.add(ChannelContext(ctx, promise))
        }
        engine.write(msg)
      }
      is DtlsPacket -> {
        // used to pass through the data for handshake packets
        // this is the underlying traffic written by this handler
        val context: ChannelContext? = writeCtxQueue.poll()
        context?.let {
          super.write(it.ctx, msg.packet, it.promise)
        } ?: run {
          super.write(ctx, msg.packet, promise)
        }
      }
      else -> super.write(ctx, msg, promise)
    }
  }

  override fun exceptionCaught(ctx: ChannelHandlerContext?, cause: Throwable?) {
    cause?.printStackTrace()
    ctx?.close()
  }

  private fun name(): String {
    return this.javaClass.toString()
  }

  protected abstract fun dtlsTransport(): DTLSTransport
}
