import React, { useState } from 'react';
import { TextInput, Button, Alert, View, StyleSheet, Text } from 'react-native';
//import { SignInUser } from '../firebase/auth';
import { useRouter } from 'expo-router';
let user: any;
export {user};



const Index = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const router = useRouter();

  const handleLogin = async () => {
    try {
      //user = await SignInUser(email, password);
      Alert.alert('Login successful');
      //router.push('/(tabs)'); // Navigate to Home (or any other tab)
    } catch (error) {
      Alert.alert('Error', 'Invalid email or password');
    }
  };

  return (
    <View style={styles.container}>
      <TextInput
        style={styles.input}
        placeholder="Email"
        value={email}
        onChangeText={(text) => setEmail(text)}
      />
      <TextInput
        style={styles.input}
        placeholder="Password"
        secureTextEntry
        value={password}
        onChangeText={(text) => setPassword(text)}
      />
      <Button
        title={'Login'}
        onPress={handleLogin}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 20,
  },
  input: {
    height: 40,
    borderColor: '#ccc',
    borderWidth: 1,
    marginBottom: 10,
    paddingLeft: 8,
  },
});

export default Index;
