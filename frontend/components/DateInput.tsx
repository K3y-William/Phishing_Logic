import React from 'react';
import { TextInput, Platform } from 'react-native';

// This component renders a native date input on web only.

export default function DateInput({ value, onChange, placeholder }) {
  if (Platform.OS === 'web') {
    return (
      <input
        type="date"
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          borderWidth: 1,
          borderColor: '#888',
          padding: 4,
          marginBottom: 8,
          marginRight: 8,
        }}
        placeholder={placeholder}
      />
    );
  } else {
    // mobile fallback, not developed
    return (
      <TextInput
        value={value}
        onChangeText={onChange}
        placeholder={placeholder}
        style={{
          borderWidth: 1,
          borderColor: '#888', //gray
          padding: 4,
          marginBottom: 8,
          marginRight: 8,
          minWidth: 120,
        }}
      />
    );
  }
}
