import React, { useState } from 'react';
import { Platform, Button, View, Text, ActivityIndicator } from 'react-native';
import { useRouter } from 'expo-router';
import { WebView } from 'react-native-webview';

const BACKEND_LOGIN_URL = 'http://localhost:5000/auth/login';

export default function LoginScreen() {
  const [showWebView, setShowWebView] = useState(false);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('');
  const router = useRouter();

  const handleLoginPress = async () => {
    if (Platform.OS === 'web') {
      setLoading(true);
      console.log("This is a test log message");
      try {
        const response = await fetch(BACKEND_LOGIN_URL);
        const data = await response.json();

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
      // Show WebView for mobile (optional)
      setShowWebView(true);
    }
  };

  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      {loading ? (
        <ActivityIndicator size="large" />
      ) : showWebView && Platform.OS !== 'web' ? (
        <WebView
          source={{ uri: BACKEND_LOGIN_URL }}
          onNavigationStateChange={(navState) => {
            if (navState.url.includes('Login successful')) {
              setShowWebView(false);
              router.push('/(tabs)');
            }
          }}
        />
      ) : (
        <>
          <Button title="Login with Gmail" onPress={handleLoginPress} />
          {status ? <Text style={{ marginTop: 20 }}>{status}</Text> : null}
        </>
      )}
    </View>
  );
}