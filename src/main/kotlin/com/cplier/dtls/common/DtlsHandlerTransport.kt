package com.cplier.dtls.common

import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.socket.DatagramPacket
import org.bouncycastle.tls.DatagramTransport
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedTransferQueue
import java.util.concurrent.TimeUnit

class DtlsHandlerTransport : DatagramTransport {

  companion object {
    private var mtu = 1500
    private val LOGGER: Logger = LoggerFactory.getLogger(DtlsHandlerTransport::class.java)

    init {
      try {
        mtu = NetworkInterface.getByInetAddress(InetAddress.getLocalHost()).mtu
      } catch (ignored: Exception) {
        LOGGER.trace("Exception occurred when getting mtu")
      }
    }

    private val RECV_BUFFER_SIZE = mtu - 32
    private val SEND_BUFFER_SIZE = mtu - 32
  }

  private var channel: Channel? = null
  private var remoteAddress: InetSocketAddress? = null

  private val readQueue: BlockingQueue<DatagramPacket> = LinkedTransferQueue()


  override fun send(buf: ByteArray?, off: Int, len: Int) {
    LOGGER.trace("send $len bytes to remoteAddress $remoteAddress")
    val packet = DatagramPacket(Unpooled.copiedBuffer(buf, off, len), remoteAddress)
    channel?.writeAndFlush(DtlsPacket(packet))
  }

  override fun receive(buf: ByteArray?, off: Int, len: Int, waitMillis: Int): Int {
    try {
      val packet = readQueue.poll(waitMillis.toLong(), TimeUnit.MILLISECONDS)
      packet?.let {
        LOGGER.trace("receive polled: $it")
        val byteBuf = it.content()
        val bytesToRead = byteBuf.readableBytes().coerceAtMost(len)
        byteBuf.readBytes(buf, off, bytesToRead)
        byteBuf.release()
        return bytesToRead
      } ?: kotlin.run {
        return 0
      }
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      return 0
    }
  }

  override fun getSendLimit(): Int = SEND_BUFFER_SIZE

  override fun getReceiveLimit(): Int = RECV_BUFFER_SIZE

  override fun close() {
    channel?.disconnect()
    channel?.deregister()
  }

  fun enqueue(msg: DatagramPacket) {
    readQueue.put(msg)
  }

  fun hasPackets(): Boolean {
    return !readQueue.isEmpty()
  }

  fun getRemoteAddress(): InetSocketAddress? {
    return remoteAddress
  }

  fun setRmoteAddress(address: InetSocketAddress?) {
    this.remoteAddress = address
  }

  fun setChannel(ch: Channel?) {
    this.channel = ch
  }
}
