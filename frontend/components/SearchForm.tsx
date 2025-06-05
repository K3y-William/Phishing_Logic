import React from 'react';
import { View, TextInput, Text, Button } from 'react-native';
import Checkbox from './checkbox';
import DateInput from './DateInput';

/**
 * A form for filtering/searching emails.
 *
 * Props:
 *   sender, setSender
 *   subject, setSubject
 *   customQuery, setCustomQuery
 *   startDate, setStartDate
 *   endDate, setEndDate
 *   hasAttachment, setHasAttachment
 *   onSearch = callback to trigger search
 */
export default function SearchForm({
  sender,
  setSender,
  subject,
  setSubject,
  customQuery,
  setCustomQuery,
  startDate,
  setStartDate,
  endDate,
  setEndDate,
  hasAttachment,
  setHasAttachment,
  onSearch,
}) {
  return (
    <View
      style={{
        backgroundColor: '#f0f0f0',
        padding: 10,
        borderRadius: 8,
        marginHorizontal: 10,
        marginBottom: 10,
      }}
    >
      <TextInput
        placeholder="Sender"
        value={sender}
        onChangeText={setSender}
        style={{ borderWidth: 1, borderColor: '#888', padding: 4, marginBottom: 8 }}
      />
      <TextInput
        placeholder="Subject"
        value={subject}
        onChangeText={setSubject}
        style={{ borderWidth: 1, borderColor: '#888', padding: 4, marginBottom: 8 }}
      />
      <TextInput
        placeholder="Custom Query"
        value={customQuery}
        onChangeText={setCustomQuery}
        style={{ borderWidth: 1, borderColor: '#888', padding: 4, marginBottom: 8 }}
      />

      <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
        <DateInput value={startDate} onChange={setStartDate} placeholder="Start Date" />
        <DateInput value={endDate} onChange={setEndDate} placeholder="End Date" />
      </View>

      <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 8 }}>
        <Checkbox value={hasAttachment} onValueChange={setHasAttachment} />
        <Text>Has Attachment</Text>
      </View>

      <Button title="Search" onPress={onSearch} />
    </View>
  );
}
