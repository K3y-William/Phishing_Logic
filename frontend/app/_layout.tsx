// app/_layout.tsx

import React from 'react';
import { Stack } from 'expo-router';

export default function RootLayout() {
  return (
    <Stack>
      <Stack.Screen
        name="index"
        options={{
          title: 'PhishingLogic',
        }}
      />
      {
      <Stack.Screen
        name="(tabs)/index"
        options={{ title: 'Inbox' }} 
      />
      }
    </Stack>
  );
}
