package com.cplier.dtls.common

import io.netty.buffer.Unpooled
import io.netty.channel.socket.DatagramPacket
import org.bouncycastle.tls.DTLSTransport
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.concurrent.BlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class DtlsEngine(private val rawTransport: DtlsHandlerTransport) {

  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(DtlsEngine::class.java)

    fun write(encTransport: DTLSTransport, packet: DatagramPacket) {
      val byteBuf = packet.content()
      val readableBytes = byteBuf.readableBytes()
      LOGGER.trace("DtlsEngine write: $packet")
      val buf = ByteArray(encTransport.sendLimit)
      byteBuf.readBytes(buf, 0, readableBytes)
      byteBuf.release()
      encTransport.send(buf, 0, readableBytes)
    }
  }

  private var encTransport: DTLSTransport? = null
  private val writeQueue: BlockingQueue<DatagramPacket> = LinkedBlockingQueue()
  private val executor = Executors.newSingleThreadScheduledExecutor()


  init {
    executor.scheduleAtFixedRate({
      encTransport?.let { it ->
        val buf = ByteArray(it.receiveLimit)
        val bytesRead = it.receive(buf, 0, buf.size, 100)
        // bad record mac issue: immediately read
        if (bytesRead > 0)
          read(DatagramPacket(Unpooled.copiedBuffer(buf, 0, bytesRead), rawTransport.getRemoteAddress()))
      }
    }, 0, 1, TimeUnit.SECONDS)

    Runtime.getRuntime().addShutdownHook(Thread(executor::shutdown))
  }

  fun read(msg: DatagramPacket): List<DatagramPacket> {
    LOGGER.trace("DtlsEngine read: $msg")
    rawTransport.enqueue(msg)
    val packets = mutableListOf<DatagramPacket>()
    encTransport?.let {
      val buf = ByteArray(it.receiveLimit)
      while (rawTransport.hasPackets()) {
        // receive waitMills must be least that heart timeout
        val bytesRead = it.receive(buf, 0, buf.size, 100)
        if (bytesRead > 0) {
          packets.add(DatagramPacket(Unpooled.copiedBuffer(buf, 0, bytesRead), rawTransport.getRemoteAddress()))
        }
      }
    }
    return packets
  }

  fun write(packet: DatagramPacket) {
    encTransport?.let { write(it, packet) } ?: run { writeQueue.add(packet) }
  }

  fun initialize(encTransport: DTLSTransport) {
    val packets = mutableListOf<DatagramPacket>()
    writeQueue.drainTo(packets)
    packets.forEach {
      Companion.write(encTransport, it)
    }
    // expose this to the outside world last to avoid race conditions
    this.encTransport = encTransport
  }

  fun isInitialized(): Boolean {
    return encTransport != null
  }
}
