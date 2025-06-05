import React, { useState } from 'react';
import {
  View,
  Text,
  Button,
  ActivityIndicator,
  Image,
  StyleSheet,
  Platform,
} from 'react-native';
import { useRouter } from 'expo-router';
import { WebView } from 'react-native-webview';

import logo from '../assets/images/phishlogo.png';

const BACKEND_LOGIN_URL = 'http://localhost:5000/auth/login';

export default function LoginScreen() {
  const router = useRouter();
  const [showWebView, setShowWebView] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('');


  const handleLoginPress = async () => {
    if (Platform.OS === 'web') { //designed foremost for web, other options not developed
      setLoading(true);
      try {
        //accesses flask endpoint for login authentication
        const response = await fetch(BACKEND_LOGIN_URL, { credentials: 'include' });
        const data = await response.json();

        //determines frontend progression
        if (data.message === 'Login successful') {
          localStorage.setItem('authenticated', 'true');
          setStatus('Login successful');
          router.push('/(tabs)');
        } else {
          setStatus(data.error || 'Unknown error occurred');
        }
      } catch (e) {
        setStatus('Login request failed. Make sure the backend is running.');
      } finally {
        setLoading(false);
      }
    } else {
      setShowWebView(true);
    }
  };

  return (
    <View style={styles.container}>
      <Image source={logo} style={styles.logo} />

      {loading ? (
        <ActivityIndicator size="large" color="#000" />
      ) : showWebView && Platform.OS !== 'web' ? (
        <WebView
          source={{ uri: BACKEND_LOGIN_URL }}
          onNavigationStateChange={(navState) => {
            if (navState.url.includes('Login successful')) {
              setShowWebView(false);
              router.push('/(tabs)');
            }
          }}
          style={styles.webview}
        />
      ) : (
        <>
          <Button title="Login with Gmail" onPress={handleLoginPress} />
          {status ? <Text style={styles.statusText}>{status}</Text> : null}
        </>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#ffffff', // white
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 20,
  },
  logo: {
    width: 480,    
    height: 480,  
    marginBottom: 40,
    resizeMode: 'contain',
  },
  statusText: {
    marginTop: 20,
    color: '#000',
    textAlign: 'center',
  },
  webview: {
    flex: 1,
    width: '100%',
  },
});
