package com.cryptorsa

import android.os.Build
import android.util.Base64
import androidx.annotation.RequiresApi
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.security.NoSuchAlgorithmException


class CryptoRsaModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String {
    return NAME
  }

  init {
    _reactContext = reactContext
  }


  @RequiresApi(Build.VERSION_CODES.M)
  @ReactMethod
  fun init(keySize:Int?, promise: Promise)  {
    runBlocking{
      try {
        cryptoRsa = CryptoRsa(_reactContext!!,keySize)
        launch {
          promise.resolve(cryptoRsa.generateKeyPair())
        }
      } catch (e: NoSuchAlgorithmException) {
        promise.reject("Error", e.message)
      } catch (e: Exception) {
        promise.reject("Error", e.message)
      }
    }
  }

  @ReactMethod
  fun getPrivateKey(promise: Promise) {
    runBlocking {
      launch { promise.resolve(cryptoRsa.privateKeyToPemString(cryptoRsa.getPrivateKey()!!))  }
    }
    // decrypt https://stackoverflow.com/questions/22900570/key-from-string-in-java-rsa
  }

  @ReactMethod
  fun getPublicKey(promise: Promise) {
    runBlocking {
      launch { promise.resolve(cryptoRsa.publicKeyToPemString(cryptoRsa.getPublicKey()!!))  }
    }
    // decrypt https://stackoverflow.com/questions/22900570/key-from-string-in-java-rsa
  }

  @ReactMethod
  fun getSHA512Text(pemString: String,promise: Promise) {
    runBlocking {
      launch { promise.resolve(cryptoRsa.getSha512Text(pemString))  }
    }
    // decrypt https://stackoverflow.com/questions/22900570/key-from-string-in-java-rsa
  }

  @RequiresApi(Build.VERSION_CODES.M)
  @ReactMethod
  fun encrypt(message: String, publicKeyBase64String: String?,promise: Promise) {
    runBlocking {
      launch { promise.resolve(cryptoRsa.encrypt(message,publicKeyBase64String))  }
    }
  }
  @ReactMethod
  fun decrypt(encryptedData: String,promise: Promise) {
    runBlocking {
      launch { promise.resolve(cryptoRsa.decrypt(encryptedData))  }
    }
  }

  companion object {
    const val NAME = "CryptoRsa"
    private lateinit var cryptoRsa: CryptoRsa
    private var _reactContext: ReactApplicationContext? = null
  }
}
