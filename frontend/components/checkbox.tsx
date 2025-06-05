import React from 'react';
import { TouchableOpacity, View } from 'react-native';

export default function Checkbox({ value, onValueChange }) {
  return (
    <TouchableOpacity
      onPress={() => onValueChange(!value)}
      style={{
        width: 20,
        height: 20,
        borderWidth: 1,
        borderColor: '#888',
        alignItems: 'center',
        justifyContent: 'center',
        marginRight: 8,
      }}
    >
      {value ? <View style={{ width: 12, height: 12, backgroundColor: '#000' }} /> : null}
    </TouchableOpacity>
  );
}
