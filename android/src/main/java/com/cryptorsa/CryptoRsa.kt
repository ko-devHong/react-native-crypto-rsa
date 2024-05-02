package com.cryptorsa


import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.WritableNativeMap
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.IOException
import java.io.Reader
import java.io.StringReader
import java.io.StringWriter
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException


class CryptoRsa(originReactContext: ReactApplicationContext, originKeySize:Int?) {

  init {
    if (originKeySize != null) {
      keySize = originKeySize
    }
    reactContext = originReactContext
  }

  private fun getAndroidKeyStore(): KeyStore {
    val keyStore = KeyStore.getInstance(KEY_STORE_TYPE)
    keyStore.load(null)

    if (keyStore.containsAlias(PRIVATE_KEY_ALIAS)) {
      keyStore.deleteEntry(PRIVATE_KEY_ALIAS);
    }
    return keyStore
  }
  private fun getEncryptedSharedPreferences(): SharedPreferences {
    val masterKey = MasterKey.Builder(reactContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
      .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
      .build()

    return EncryptedSharedPreferences.create(
      reactContext,
      PREFERENCE_NAME,
      masterKey,
      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
  }

  private fun getCipher(): Cipher {
    return try {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) { // below android m
        Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL") // error in android 6: InvalidKeyException: Need RSA private or public key
      } else { // android m and above
        Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidKeyStoreBCWorkaround") // error in android 5: NoSuchProviderException: Provider not available: AndroidKeyStoreBCWorkaround
      }
    } catch (exception: Exception) {
      throw RuntimeException("getCipher: Failed to get an instance of Cipher", exception)
    }
  }

  @Throws(IOException::class)
  @RequiresApi(Build.VERSION_CODES.M)
  fun generateKeyPair(): WritableNativeMap {
    reactKeyStore = getAndroidKeyStore()
    val keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM,KEY_STORE_TYPE)
    // NOTE : https://stackoverflow.com/questions/42570020/invalidkeyexception-keystore-operation-failed-on-rsa-decrypt-on-android-device
    keyGen.initialize(KeyGenParameterSpec.Builder(
      PRIVATE_KEY_ALIAS,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
      .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
      .setRandomizedEncryptionRequired(true)
      .build())
      keyGen.generateKeyPair()
    val keys = WritableNativeMap()
    val publicKey = publicKeyToPemString(getPublicKey()!!)
//    val encryptedSharedPreferences = getEncryptedSharedPreferences()
//    val edit = encryptedSharedPreferences.edit()
//    edit.putString(PUBLIC_HEADER,publicKey)
//    edit.putString(PRIVATE_HEADER,getPrivateKey().toString())
//    edit.apply();
//    Log.d(TAG,"encryptedSharedPreferences ${encryptedSharedPreferences.getString(PUBLIC_HEADER,"") ?:""}")

    // https://stackoverflow.com/questions/22664809/encode-with-private-key-in-androidkeystore-return-null
//    val privateKey = privateKeyToPemString(getPrivateKey()!!)
//    keys.putString("private", privateKey)
    keys.putString("publicKey", publicKey)
    return keys
  }

  @Throws(IOException::class)
  fun getSha512Text(pemString: String): String {
    val byteArray = pemStringToRSAKeyByteArray(pemString)
    val md: MessageDigest = MessageDigest.getInstance("SHA-512")
    val messageDigest = md.digest(byteArray)

    // Convert byte array into signum representation
    val no = BigInteger(1, messageDigest)

    // Convert message digest into hex value
    var hashtext: String = no.toString(16)

    // Add preceding 0s to make it 128 chars long
    while (hashtext.length < 128) {
      hashtext = "0$hashtext"
    }
    return hashtext
  }

  @Throws(IOException::class)
  private fun privateKeyToPkcs1(privateKey: PrivateKey): ByteArray {
    val pkInfo = PrivateKeyInfo.getInstance(privateKey.encoded)
    val asN1Encode = pkInfo.parsePrivateKey()
    val primitive = asN1Encode.toASN1Primitive()
    return primitive.getEncoded()
  }

  @Throws(IOException::class)
  fun publicKeyToPemString(publicKey: PublicKey): String {
    val pemObject = PemObject(PUBLIC_HEADER, publicKey.encoded)
    val stringWriter = StringWriter()
    val pemWriter = PemWriter(stringWriter)
    pemWriter.writeObject(pemObject)
    pemWriter.close()
    return stringWriter.toString();
  }

  @Throws(IOException::class)
  fun privateKeyToPemString(privateKey: PrivateKey): String {
    val byteArray = privateKeyToPkcs1(privateKey)
    val pemObject = PemObject(PRIVATE_HEADER, byteArray)
    val stringWriter = StringWriter()
    val pemWriter = PemWriter(stringWriter)
    pemWriter.writeObject(pemObject)
    pemWriter.close()
    return stringWriter.toString();
  }

  @Throws(IOException::class)
  private fun pemStringToRSAKeyByteArray(pemString: String): ByteArray? {
    var keyReader: Reader? = null
    try{
      keyReader = StringReader(pemString)
      val pemReader = PemReader(keyReader)
      val pemObject = pemReader.readPemObject()
      return pemObject.content
    } finally {
      keyReader?.close()
    }
  }

  @RequiresApi(Build.VERSION_CODES.M)
  private fun convertPrivateKeyFromPem(pemString: String): PrivateKey? {
    val privateByteArray = pemStringToRSAKeyByteArray(pemString)
    val asN1InputStream = ASN1InputStream(privateByteArray)
    val obj: ASN1Primitive = asN1InputStream.readObject()
    val keyStruct: RSAPrivateKey = RSAPrivateKey.getInstance(obj)
    val keySpec = RSAPrivateKeySpec(keyStruct.modulus, keyStruct.privateExponent)
    val keyFactory = KeyFactory.getInstance(RSA_ALGORITHM)
    return keyFactory.generatePrivate(keySpec)
  }

  @RequiresApi(Build.VERSION_CODES.M)
  private fun convertPublicKeyFromPem(pemString: String): PublicKey? {
    var keyReader: StringReader? = null
     try {
      keyReader = StringReader(pemString)
      val pemParser = PemReader(keyReader)
      val subjectPublicKeyInfo = pemParser.readPemObject()
       // Check if the object type is "RSA PUBLIC KEY"
       if (subjectPublicKeyInfo.type != PUBLIC_HEADER) {
         Log.w(TAG,"Invalid PEM object type :  ${subjectPublicKeyInfo.type}")
         throw RuntimeException("Invalid PEM object type: ${subjectPublicKeyInfo.type}")
       }
       val spec = X509EncodedKeySpec(subjectPublicKeyInfo.content)
       return  KeyFactory.getInstance(RSA_ALGORITHM).generatePublic(spec)
    } catch (e:Exception) {
       Log.e(TAG,"getPublicKey : ${getPublicKey()}")
      Log.e(TAG,"pemString : $pemString")
      Log.e(TAG,e.stackTraceToString())
       throw e
    } finally {
       keyReader?.close()
    }
  }


  fun getPrivateKey(): PrivateKey? {
    val keyStore = reactKeyStore
    val entry: KeyStore.Entry = keyStore.getEntry(PRIVATE_KEY_ALIAS, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      Log.w(TAG, "Not an instance of a PrivateKeyEntry")
      return null
    }
    return entry.privateKey
  }

  fun getPublicKey(): PublicKey? {
    val keyStore = reactKeyStore
    val entry: KeyStore.Entry = keyStore.getEntry(PRIVATE_KEY_ALIAS, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      Log.w(TAG, "Not an instance of a PrivateKeyEntry")
      return null
    }
    return entry.certificate.publicKey
  }

  @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class, IllegalBlockSizeException::class, BadPaddingException::class, NoSuchPaddingException::class, InvalidKeyException::class)
  @RequiresApi(Build.VERSION_CODES.M)
  fun encrypt(message: String, sendPublicKey: String? = ""): String? {
    var publicKey = getPublicKey()
    if(sendPublicKey != "") {
      publicKey  = convertPublicKeyFromPem(sendPublicKey as String)
    }
    if(publicKey == null) return null
    val cipher = getCipher()
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    val encodedBytes = cipher.doFinal(message.toByteArray(Charsets.UTF_8))
    return Base64.encodeToString(encodedBytes,Base64.DEFAULT)
  }

  @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class, IllegalBlockSizeException::class, BadPaddingException::class, NoSuchPaddingException::class, InvalidKeyException::class)
  fun decrypt(encryptedDataString: String): String? {
    val decryptedData = Base64.decode(encryptedDataString,Base64.DEFAULT)
    val privateKey = getPrivateKey() ?: return null
    Log.d(TAG,"decrypt privateKey : $privateKey")
    Log.d(TAG,"decrypt decryptedData : $decryptedData")
    val cipher = getCipher()
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    return String(cipher.doFinal(decryptedData), Charsets.UTF_8)
  }

  companion object {
    private var keySize = 2048
    private lateinit var reactContext: ReactApplicationContext;
    private lateinit var reactKeyStore: KeyStore;
    private const val KEY_STORE_TYPE = "AndroidKeyStore"
    private const val PREFERENCE_NAME = "ReactNativeRsaPreferences"
    private const val PRIVATE_KEY_ALIAS = "ReactNativeRsaPrivateKey"
    private const val PUBLIC_HEADER = "PUBLIC KEY"
    private const val PRIVATE_HEADER = "PRIVATE KEY"
    private const val TAG = "ReactNativeRsa"
    @RequiresApi(Build.VERSION_CODES.M)
    private const val RSA_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA;
  }
}
