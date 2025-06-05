import React from 'react';
import { View, Text, TouchableOpacity } from 'react-native';

function getRiskColor(analysisText) {
  if (!analysisText) return '#e0e0e0'; // Default darker gray

  // Match in order so "Very High" won’t be picked up as just "High"
  if (/\bVery High\b/.test(analysisText)) return '#F44336';  // Red
  if (/\bHigh\b/.test(analysisText))      return '#FF9800';  // Orange
  if (/\bMedium\b/.test(analysisText))    return '#FFEB3B';  // Yellow
  if (/\bVery Low\b/.test(analysisText))  return '#C8E6C9';  // Light green
  if (/\bLow\b/.test(analysisText))       return '#4CAF50';  // Green

  return '#e0e0e0'; // Fallback
}

/**
 * - single email row. 
 * - Shows sender & subject when minimized
 * - Expands to show `analysis.analysis` text when pressed
 */
export default function EmailItem({ item, expandedId, setExpandedId }) {
  const isExpanded = expandedId === item.id;
  const riskColor = getRiskColor(item.analysis?.analysis || '');

  return (
    <View style={{ marginVertical: 2 }}>
      <TouchableOpacity
        onPress={() => setExpandedId(item.id)}
        disabled={isExpanded}
        style={{
          padding: 10,
          backgroundColor: riskColor,
        }}
      >
        <Text>
          {item.from} — {item.subject}
        </Text>
      </TouchableOpacity>

      {isExpanded && (
        //light gray
        <View style={{ padding: 10, backgroundColor: '#f9f9f9' }}> 
          <Text>{item.analysis.analysis}</Text>
          <TouchableOpacity onPress={() => setExpandedId(null)}>
            <Text style={{ color: 'blue', marginTop: 8 }}>Minimize</Text>
          </TouchableOpacity>
        </View>
      )}
    </View>
  );
}
