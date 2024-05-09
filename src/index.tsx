import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-crypto-rsa' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const CryptoRsa = NativeModules.CryptoRsa
  ? NativeModules.CryptoRsa
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

class CryptoRsaClass {
  private instance = CryptoRsa;
  async init(
    keySize: number = 2048
  ): Promise<{ publicKey: string; privateKey?: string }> {
    return await this.instance.generateKeys(keySize);
  }

  async getPrivateKey(): Promise<string> {
    return await this.instance.getPrivateKey();
  }
  async getPublicKey(): Promise<string> {
    return await this.instance.getPublicKey();
  }

  async encrypt(message: string, publicKey: string): Promise<string> {
    return await this.instance.encrypt(message, publicKey);
  }

  async decrypt(encryptBase64String: string): Promise<string> {
    return await this.instance.decrypt(encryptBase64String);
  }

  async getSHA512Text(pemString: string): Promise<string> {
    return await this.instance.getSHA512Text(pemString);
  }

  async base64Decode(base64String: string): Promise<string> {
    return await this.instance.base64Decode(base64String);
  }

  async base64Encode(message: string): Promise<string> {
    return await this.instance.base64Encode(message);
  }
}

const RNCryptoRsa = new CryptoRsaClass();

export default RNCryptoRsa;
