package com.cplier

import com.cplier.view.MainView
import tornadofx.*
import kotlin.system.exitProcess

class FxApp : App(MainView::class, Styles::class) {
  override fun stop() {
    super.stop()
    // system exit
    exitProcess(0)
  }
}
