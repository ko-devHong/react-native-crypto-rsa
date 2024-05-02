# @ko-developerhong/react-native-crypto-rsa

## introduce
>`@ko-developerhong/react-native-crypto-rsa` The library provides RSA encryption and decryption in React Native applications, which allow you to generate public and private keys, and encrypt or decrypt messages.

## Installation

```sh
npm install @ko-developerhong/react-native-crypto-rsa
```

## iOS
1. Add the following lines to the Podfile.
```Podfile
pod 'react-native-crypto-rsa', :path => '../node_modules/react-native-crypto-rsa'
```
2. From the terminal, go to the root directory of the project and issue the `pod install` command.
```shell
cd ios
pod install
# OR
npx pod-install ios
```
### Manual Installation
> `Xcode`를 열고, 프로젝트 파일을 클릭한 후, `Build Phases` 탭에서 `Link Binary With Libraries` 섹션에 `libreact-native-crypto-rsa.a`를 추가합니다.

## Usage

### Generating public and private keys
- The `publicKey` value is returned in the form of a `pemString`.
```tsx
import RNCryptoRsa from '@ko-developerhong/react-native-crypto-rsa';

// keySize: An integer value representing the size of the key to be generated. The default is 2048.
const keySize = 2048
const { publicKey } = await RNCryptoRsa.init(keySize);
const publicKeyPemString = await RNCryptoRsa.getPublicKey();
```

### Encrypt and decrypt messages
```tsx
import RNCryptoRsa from '@ko-developerhong/react-native-crypto-rsa';

const encryptedMessage = await RNCryptoRsa.encrypt('Hello, World!', publicKey);
const decryptedMessage = await RNCryptoRsa.decrypt(encryptedMessage); // Hello, World!
```

### SHA512 hash generation
```tsx
import RNCryptoRsa from '@ko-developerhong/react-native-crypto-rsa';

const { publicKey } = await RNCryptoRsa.init(keySize);
const sha512Text = await RNCryptoRsa.getSHA512Text(publicKey); // hashText
```

## Precautions
> RSA encryption and decryption are CPU and memory intensive, which can affect performance when handling large amounts of data.
> Public and private keys are critical to security, so they should be stored in a secure place and deleted if unnecessary.
> The public key is used to encrypt the message, and the private key is used to decrypt the encrypted message.

## Example
```shell
yarn example start

yarn example android
# OR
yarn example ios
```

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
