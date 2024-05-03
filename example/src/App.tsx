import * as React from 'react';
import { useEffect, useState } from 'react';

import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import RNCryptoRsa from '@ko-developerhong/react-native-crypto-rsa';

export default function App() {
  const [result, setResult] = useState<string | undefined>();
  const [base64String, setBase64String] = useState('');
  const [publicString, setPublicString] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const { publicKey } = await RNCryptoRsa.init();
        setPublicString(publicKey);
        console.log('@publicKey  : ', publicKey);
        // console.log('privateKey : ', privateKey);
        const encryptBase64String = await RNCryptoRsa.encrypt(
          'hello world',
          publicKey
        );
        console.log('@encryptBase64String : ', encryptBase64String);
        RNCryptoRsa.decrypt(encryptBase64String)
          .then((rrr) => {
            console.log('@decrypt String : ', rrr);
          })
          .catch(console.error);
      } catch (e) {
        console.error('error : ', e);
      }
    })();
  }, []);

  const decryptString = async () => {
    console.log('base64String : ', base64String);
    const originString = await RNCryptoRsa.decrypt(base64String);
    setResult(originString);
  };

  return (
    <View style={styles.container}>
      <TextInput
        style={{
          marginTop: 30,
          width: '90%',
          marginHorizontal: 20,
          borderWidth: 1,
          height: 200,
          borderColor: 'gray',
        }}
        onChangeText={setBase64String}
        value={base64String}
      />
      <Text>publicKey : {publicString} </Text>
      <Text>Result: {result}</Text>
      <Pressable
        style={{ backgroundColor: 'skyblue', padding: 10, marginTop: 20 }}
        onPress={decryptString}
      >
        <Text>Press decrypt</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
