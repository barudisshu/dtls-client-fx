package com.cplier.dtls.common

import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.socket.DatagramPacket
import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.DatagramTransport
import org.bouncycastle.tls.TlsFatalAlert
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class DtlsHandlerTransport : DatagramTransport {

  companion object {
    private var mtu = 1500
    private val LOGGER: Logger = LoggerFactory.getLogger(DtlsHandlerTransport::class.java)

    init {
      try {
        mtu = NetworkInterface.getByInetAddress(InetAddress.getLocalHost()).mtu.coerceAtMost(mtu)
      } catch (ignored: Exception) {
        LOGGER.trace("Exception occurred when getting mtu")
      }
    }

    private const val MIN_IP_OVERHEAD = 20
    private const val MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64
    private const val UDP_OVERHEAD = 8

    private val RECV_BUFFER_SIZE = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD
    private val SEND_BUFFER_SIZE = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD
  }

  private var channel: Channel? = null
  private var remoteAddress: InetSocketAddress? = null

  private val readQueue: BlockingQueue<DatagramPacket> = LinkedBlockingQueue()


  override fun send(buf: ByteArray?, off: Int, len: Int) {
    if (len > sendLimit) {
      /*
       * RFC 4347 4.1.1. "If the application attempts to send a record larger than the MTU,
       * the DTLS implementation SHOULD generate an error, thus avoiding sending a packet
       * which will be fragmented."
       */
      throw TlsFatalAlert(AlertDescription.internal_error)
    } else {
      LOGGER.trace("send $len bytes to remoteAddress $remoteAddress")
      val packet = DatagramPacket(Unpooled.copiedBuffer(buf, off, len), remoteAddress)
      channel?.writeAndFlush(DtlsPacket(packet))
    }
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
        return -1
      }
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      return -1
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
