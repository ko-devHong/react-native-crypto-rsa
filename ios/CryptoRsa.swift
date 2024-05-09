
import Foundation
import CommonCrypto
import Security

extension String {
    
    public var sha512: String {
        let data = self.data(using: .utf8) ?? Data()
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map({ String(format: "%02hhx", $0) }).joined(separator: "")
    }
}

@objc(CryptoRsa)
class CryptoRsa: NSObject {
    let publicTag = "ko.dev.hong.rn.public"
    let privateTag = "ko.dev.hong.rn.private"
    let secKeyAlgorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
    static var privateKeyValue: SecKey?;
    
    struct RuntimeError: LocalizedError {
        let description: String
        
        init(_ description: String) {
            self.description = description
        }
        
        var errorDescription: String? {
            description
        }
    }
    
    func getKeyFromKeychain(tag: String) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        ]
        if(tag == publicTag) {
            query[kSecReturnData as String] = kCFBooleanTrue ?? true
        } else {
            query[kSecReturnRef as String] = true
        }
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            print("Error retrieving key from keychain: \(status)")
            return nil
        }
        
        return (item as! SecKey)
    }
    
    func base64EncodeString(_ data: Data) -> String {
        return data.base64EncodedString(options: .lineLength64Characters)
    }
    
    func base64Decode(_ string: String) -> Data? {
        return Data(base64Encoded: string,options: .ignoreUnknownCharacters)
    }
    
    func appendPrefixSuffixTo(_ string: String, prefix: String, suffix: String) -> String {
        return "\(prefix)\(string)\(suffix)"
    }
    
    func publicKeyToPemString(_ publicKey: SecKey) -> String {
        var error: Unmanaged<CFError>?
        // client public key to pem string
        guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            print("Failed to get external representation of public key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return ""
        }
        let finalPemString = base64EncodeString(keyData)
        let clientPublicKeyString = appendPrefixSuffixTo(finalPemString, prefix: "-----BEGIN PUBLIC KEY-----\r\n", suffix: "\r\n-----END PUBLIC KEY-----\r\n")
        return clientPublicKeyString
    }
    
    func privateKeyToPemString(_ privateKey: SecKey) -> String {
        var error: Unmanaged<CFError>?
        // client public key to pem string
        guard let keyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            print("Failed to get external representation of private Key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return ""
        }
        let finalPemString = base64EncodeString(keyData)
        let clientPrivateKeyString = appendPrefixSuffixTo(finalPemString, prefix: "-----BEGIN PRIVATE KEY-----\r\n", suffix: "\r\n-----END PRIVATE KEY-----\r\n")
        return clientPrivateKeyString
    }
    
    func pemStringToPublicKey(_ pemString: String) -> SecKey? {
        var pemCleaned = pemString
        pemCleaned = pemCleaned.replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        pemCleaned = pemCleaned.replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
        pemCleaned = pemCleaned.replacingOccurrences(of: "\r\n", with: "")
        pemCleaned = pemCleaned.replacingOccurrences(of: "\n", with: "")
        
        guard let data = base64Decode(pemCleaned) else {
            print("base64 decode faild")
            return nil
        }
        
        let options: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(data as CFData, options as CFDictionary, &error) else {
            if let error = error {
                print("SecKeyCreateWithData failed with error: \(error.takeRetainedValue())")
            } else {
                print("SecKeyCreateWithData failed.")
            }
            return nil
        }
        
        return publicKey
    }
    
    @objc(generateKeys:withResolver:withRejecter:)
    func generateKeys(keySize: Int,resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        //     let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator
        //kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        //     .privateKeyUsage,
        //     nil) // Ignore any error
        
        let publicKeyParameters: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true as AnyObject,
            //     kSecAttrAccessControl as String: access!,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecAttrApplicationTag as String: publicTag.data(using: .utf8)! as AnyObject
        ]
        let privateKeyParameters: [String: AnyObject] = [
            kSecAttrIsPermanent as String: true as AnyObject,
            //     kSecAttrAccessControl as String: access!,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecAttrApplicationTag as String: privateTag.data(using: .utf8)! as AnyObject
        ]
        let parameters: [String: AnyObject] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize as AnyObject,
            kSecPublicKeyAttrs as String: publicKeyParameters as AnyObject,
            kSecPrivateKeyAttrs as String: privateKeyParameters as AnyObject,
        ]
        
        var publicKey, privateKey: SecKey?
        if #available(iOS 10.0, *) {
            
            var error: Unmanaged<CFError>?
            privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error)
            
            if privateKey == nil {
                print("Error occured: keys weren't created")
                return reject(nil, nil, RuntimeError("Error occured: keys weren't created"))
            }
            
            publicKey = SecKeyCopyPublicKey(privateKey!)
            
        } else {
            // Fallback on earlier versions
            
            let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
            
            guard status == errSecSuccess else {
                print("Error generating key pair: \(status)")
                return reject(nil, nil, RuntimeError("Error generating key pair: \(status)"))
            }
        }
        
        let keys = ["publicKey": publicKeyToPemString(publicKey!), "privateKey": privateKeyToPemString(privateKey!)]
        
        resolve(keys)
    }
    
    @objc(encrypt:withPublicKey:withResolver:withRejecter:)
    func encrypt(message: String, pemString: String,resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Void {
        guard let data = message.data(using: .utf8) else { return reject(nil,nil,RuntimeError("Data is null")) }
        
        // 데이터 크기 확인 (예시: RSA 키 크기 2048비트, 최대 데이터 크기 245바이트)
        if data.count > 245 {
            return reject(nil, nil, RuntimeError("Data size too large for RSA encryption"))
        }
        
        guard let publicKey = pemStringToPublicKey(pemString) else {
            return reject(nil,nil,RuntimeError("pemStringTopublicKey is null"))
        }
        
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, secKeyAlgorithm) else { return reject(nil,nil,RuntimeError("SecKeyIsAlgorithm not supported")) }
        var error: Unmanaged<CFError>?
        
        guard let cipherData = SecKeyCreateEncryptedData(publicKey,
                                                         secKeyAlgorithm,
                                                         data as CFData,
                                                         &error) as Data? else {
            print("Encryption error: \((error?.takeRetainedValue())!)")
            return reject(nil, nil, RuntimeError("Encryption error: \((error?.takeRetainedValue())!)"))
        }
        
        resolve(base64EncodeString(cipherData))
    }
    
    @objc(decrypt:withResolver:withRejecter:)
    func decrypt(encryptedDataString: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) -> Any? {
        guard let encryptedData = base64Decode(encryptedDataString) else {
            print("base64Decode Failed")
            return reject(nil, nil, RuntimeError("base64Decode Failed"))
        }
        
        guard let loadedPrivateKey = getKeyFromKeychain(tag: privateTag) else {
            print("Load Failed privateKey in KeyChain")
            reject(nil, nil, RuntimeError("Keychain Load failed"))
            return nil
        }
        
        // Check if the encrypted data size matches the key size
        let blockSize = SecKeyGetBlockSize(loadedPrivateKey)
        if encryptedData.count != blockSize {
            print("Encrypted data size does not match key block size")
            reject(nil, nil, RuntimeError("Encrypted data size does not match key block size"))
            return nil
        }
        
        guard SecKeyIsAlgorithmSupported(loadedPrivateKey, .decrypt, secKeyAlgorithm) else {
            reject(nil, nil, RuntimeError("SecKeyIsAlgorithm not supported"))
            return nil
        }
        
        var error: Unmanaged<CFError>?
        guard let clearData = SecKeyCreateDecryptedData(loadedPrivateKey, secKeyAlgorithm, encryptedData as CFData, &error) as Data? else {
            print("Decryption error: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
            return reject(nil, nil, RuntimeError("Decryption error: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")"))
        }
        
        return resolve(String(data: clearData, encoding: .utf8))
    }
    
    @objc(getSHA512Text:withResolver:withRejecter:)
    func getSHA512Text(pemString: String, resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) {
        let sha512String = pemString.sha512
        resolve(sha512String)
    }
    
    @objc(getPrivateKey:withRejecter:)
    func getPrivateKey(resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) {
        guard let loadedPrivateKey = getKeyFromKeychain(tag: privateTag ) else {
            print("Load Faild privateKey in KeyChain ")
            return reject(nil,nil,RuntimeError("Keychain Load failed"))
        }
        print("Load privateKey in KeyChain :", loadedPrivateKey)
        resolve(loadedPrivateKey)
    }
    
    @objc(getPublicKey:withRejecter:)
    func getPublicKey(resolve:RCTPromiseResolveBlock,reject:RCTPromiseRejectBlock) {
        guard let loadedPublicKey = getKeyFromKeychain(tag: publicTag ) else {
            print("Load Faild PublicKey in KeyChain ")
            return reject(nil,nil,RuntimeError("Keychain Load failed"))
        }
        print("Load privateKey in KeyChain :", loadedPublicKey)
        resolve(loadedPublicKey)
    }
}
