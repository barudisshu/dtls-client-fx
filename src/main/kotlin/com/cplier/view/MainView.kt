package com.cplier.view

import com.cplier.app.DtlsClientCertModifier
import com.cplier.app.DtlsNettyClient
import javafx.beans.property.SimpleStringProperty
import javafx.geometry.Orientation.VERTICAL
import javafx.geometry.Pos
import javafx.scene.control.ButtonBar
import javafx.scene.layout.Priority
import javafx.scene.paint.Color
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import tornadofx.*

class CertC(root: String? = null, pub: String? = null, pri: String? = null) {
  val rootProperty = SimpleStringProperty(this, "root", root)
  var root: String by rootProperty

  val pubProperty = SimpleStringProperty(this, "pub", pub)
  var pub: String by pubProperty

  val priProperty = SimpleStringProperty(this, "pri", pri)
  var pri: String by priProperty
}

class Traffic(packet: String? = null) {
  val packetProperty = SimpleStringProperty(this, "packet", packet)
  val packet: String by packetProperty
}

class Console(msg: String? = null) {
  val msgProperty = SimpleStringProperty(this, "msg", msg)
  var msg: String by msgProperty
}


class MainView : View("DTLS Client") {

  private val udpModel = UdpModel(Traffic())
  private val certModel = CertCModel(CertC())
  private var console = Console("logging information")
  private val consoleModel = ConsoleModel(console)


  override val root = borderpane {
    top = stackpane {
      button("IP Flow Information Export") {
        useMaxHeight = true
        useMaxWidth = true
        style {
          backgroundColor += Color.DARKCYAN
          fontSize = 40.0.px
        }
      }
    }
    center = vbox {
      form {
        hbox {
          fieldset("DTLS fields", labelPosition = VERTICAL) {
            field("IPFIX data record", VERTICAL) {
              textarea(udpModel.datagramPacket) {
                isWrapText = true
                prefRowCount = 5
                vgrow = Priority.ALWAYS
                required()
                whenDocked { requestFocus() }
              }
            }
            buttonbar {
              button("Send").action {
                udpModel.commit {
                  CoroutineScope(Dispatchers.IO).launch {
                    doSend()
                  }
                }
              }
            }
          }
        }
      }
      useMaxWidth = true
    }
    right = vbox {
      form {
        fieldset("load certificates", labelPosition = VERTICAL) {
          field("root", VERTICAL) {
            textfield(certModel.root).validator {
              if (it.isNullOrBlank()) error("root path is required") else null
            }
          }
          field("public key", VERTICAL) {
            textfield(certModel.pub).validator {
              if (it.isNullOrBlank()) error("public key path is required") else null
            }
          }
          field("private key", VERTICAL) {
            textfield(certModel.pri) {
              validator {
                if (it.isNullOrBlank()) error("private key file path is required") else null
              }
            }
          }
        }
        buttonbar {
          button("Load", ButtonBar.ButtonData.OK_DONE) {
            enableWhen(certModel.valid)
            action {
              certModel.commit()
              loadCert()
            }
          }
          button("Reset").setOnAction { certModel.rollback() }
        }
      }
    }
    bottom = squeezebox {
      fold("Console", expanded = true) {
        stackpane {
          label(consoleModel.msg)
          useMaxHeight = true
          useMaxWidth = true
          style {
            backgroundColor += Color.DARKGRAY
            fontSize = 24.0.px
            alignment = Pos.CENTER
          }
        }
      }
    }
  }

  class UdpModel(traffic: Traffic) : ItemViewModel<Traffic>(traffic) {
    val datagramPacket = bind(Traffic::packetProperty)
  }

  class CertCModel(certC: CertC) : ItemViewModel<CertC>(certC) {
    val root = bind(CertC::rootProperty)
    val pub = bind(CertC::pubProperty)
    val pri = bind(CertC::priProperty)
  }

  class ConsoleModel(console: Console) : ItemViewModel<Console>(console) {
    val msg = bind(Console::msgProperty)
  }

  // do send udp packet
  private suspend fun doSend() {
    val data = udpModel.item.packet
    val job = CoroutineScope(Dispatchers.IO).async {
      kotlin.runCatching {
        DtlsNettyClient.send(data)
      }
    }
    job.join()
  }

  // load certificates of the client side
  private fun loadCert() {
    val certC = certModel.item
    certC load DtlsClientCertModifier

    console.msg = "loading certificates successfully, remote port: 4740"
  }
}

infix fun CertC.load(holder: DtlsClientCertModifier) {
  holder.rootPath = this.root
  holder.pubPath = this.pub
  holder.priPath = this.pri
}
