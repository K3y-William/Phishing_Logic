import React, { useState } from 'react';
import {
  View,
  FlatList,
  Text,
  ActivityIndicator,
  Button,
} from 'react-native';

import SearchForm from '../../components/SearchForm';
import EmailItem from '../../components/EmailItem';
import useEmailData from '../hooks/useEmailData';

export default function Tab() {
  // 1) Pull in data + loading + searchEmails from hook
  const { data, loading, searchEmails } = useEmailData();

  // 2) Track which email is expanded
  const [expandedId, setExpandedId] = useState(null);

  // 3) Search fields have local state
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [customQuery, setCustomQuery] = useState('');
  const [startDate, setStartDate] = useState('');  // "YYYY-MM-DD"
  const [endDate, setEndDate] = useState('');  
  const [hasAttachment, setHasAttachment] = useState(false);

  // 4) Search form visibility
  const [searchOpen, setSearchOpen] = useState(false);

  // 5) Search form handler
  const handleSearch = () => {
    searchEmails({
      sender,
      subject,
      customQuery,
      startDate,
      endDate,
      hasAttachment,
    });
  };

  return (
    <View style={{ flex: 1 }}>
      {/* Search button */}
      <View style={{ padding: 10, flexDirection: 'row', justifyContent: 'flex-end' }}>
        <Button
          title={searchOpen ? 'Close Search' : 'Search'}
          onPress={() => setSearchOpen(prev => !prev)}
        />
      </View>

      {/* Show the search form only if requested */}
      {searchOpen && (
        <SearchForm
          sender={sender}
          setSender={setSender}
          subject={subject}
          setSubject={setSubject}
          customQuery={customQuery}
          setCustomQuery={setCustomQuery}
          startDate={startDate}
          setStartDate={setStartDate}
          endDate={endDate}
          setEndDate={setEndDate}
          hasAttachment={hasAttachment}
          setHasAttachment={setHasAttachment}
          onSearch={handleSearch}
        />
      )}

      {/* A loading indicator when fetching/searching */}
      {loading && (
        <View style={{ alignItems: 'center', padding: 10 }}>
          <ActivityIndicator size="large" />
          <Text style={{ marginTop: 8 }}>Scanning inbox...</Text>
        </View>
      )}

      {/* The list of emails */}
      <FlatList
        data={data}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <EmailItem
            item={item}
            expandedId={expandedId}
            setExpandedId={setExpandedId}
          />
        )}
        ListEmptyComponent={
          !loading && (
            <Text style={{ padding: 20, textAlign: 'center' }}>
              No emails found.
            </Text>
          )
        }
      />
    </View>
  );
}
