import React, { useState, useEffect } from 'react';
import { FlatList, Text, TouchableOpacity, View, ActivityIndicator } from 'react-native';

export default function Tab() {
  const [data, setData] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const [loading, setLoading] = useState(false);

  async function fetchEmails() {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:5000/scan/list', {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Network response was not ok');
      const result = await response.json();
      setData(result.messages || []);
    } catch (error) {
      console.error('Fetch operation failed:', error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchEmails();
    const intervalId = setInterval(fetchEmails, 2 * 60 * 1000);
    return () => clearInterval(intervalId);
  }, []);

  const renderItem = ({ item }) => {
    const isExpanded = expandedId === item.id;
    return (
      <View style={{ marginVertical: 2 }}>
        <TouchableOpacity
          onPress={() => setExpandedId(item.id)}
          disabled={isExpanded}
          style={{ padding: 10, backgroundColor: '#eee' }}
        >
          <Text>{item.from} — {item.subject}</Text>
        </TouchableOpacity>
        {isExpanded && (
          <View style={{ padding: 10, backgroundColor: '#f9f9f9' }}>
            <Text>{item.scanOutput}</Text>
            <TouchableOpacity onPress={() => setExpandedId(null)}>
              <Text style={{ color: 'blue', marginTop: 8 }}>Minimize</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>
    );
  };

  return (
    <FlatList
      data={data}
      keyExtractor={item => item.id}
      renderItem={renderItem}
      ListEmptyComponent={
        loading ? (
          <View style={{ alignItems: 'center', padding: 20 }}>
            <ActivityIndicator size="large" />
            <Text style={{ marginTop: 12 }}>Scanning inbox...</Text>
          </View>
        ) : (
          <Text style={{ padding: 20, textAlign: 'center' }}>No emails found.</Text>
        )
      }
    />
  );
}