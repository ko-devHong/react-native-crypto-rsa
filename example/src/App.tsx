import * as React from 'react';
import { useEffect } from 'react';

import { StyleSheet, Text, View } from 'react-native';
import RNCryptoRsa from '@ko-developerhong/react-native-crypto-rsa';

export default function App() {
  const [result, setResult] = React.useState<string | undefined>();

  useEffect(() => {
    (async () => {
      const { publicKey } = await RNCryptoRsa.init();
      const encryptBase64String = await RNCryptoRsa.encrypt(
        'hello world',
        publicKey
      );
      const originString = await RNCryptoRsa.decrypt(encryptBase64String);
      setResult(originString);
    })();
  }, []);

  return (
    <View style={styles.container}>
      <Text>Result: {result}</Text>
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
