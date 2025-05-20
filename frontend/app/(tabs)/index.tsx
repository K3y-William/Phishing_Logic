import React, { useState, useEffect } from 'react';
import { FlatList, Text, TouchableOpacity, Alert } from 'react-native';

export default function Tab() {
  const [data, setData] = useState([]);

  // Async function to fetch emails from the backend
  async function fetchEmails() {
    try {
      const response = await fetch('http://localhost:5000/scan/list', {
        credentials: 'include', // If your Flask app uses session cookies
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const result = await response.json();

      // Assuming backend returns { messages: [ { id, title }, ... ] }
      setData(result.messages || []);
    } catch (error) {
      console.error('Fetch operation failed:', error);
    }
  }

  // Poll every 2 minutes
  useEffect(() => {
    fetchEmails(); // Initial fetch on mount

    const intervalId = setInterval(() => {
      fetchEmails();
    }, 2 * 60 * 1000); // 2 minutes

    return () => clearInterval(intervalId); // Clean up on unmount
  }, []);

  const handlePress = (item) => {
    Alert.alert('You pressed', item.title);
  };

  const renderItem = ({ item }) => (
    <TouchableOpacity
      style={{
        padding: 10,
        backgroundColor: '#4CAF50',
        marginVertical: 2,
        borderRadius: 10,
      }}
      onPress={() => handlePress(item)}
    >
      <Text style={{ color: 'white', fontSize: 16 }}>{item.title}</Text>
    </TouchableOpacity>
  );

  return (
    <FlatList
      data={data}
      keyExtractor={(item) => item.id}
      renderItem={renderItem}
      ListEmptyComponent={<Text style={{ padding: 20, textAlign: 'center' }}>No emails found.</Text>}
    />
  );
}