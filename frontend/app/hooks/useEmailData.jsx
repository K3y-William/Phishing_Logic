// frontend/app/hooks/useEmailData.js
import { useState, useEffect, useRef } from 'react';

//2 minute interval
export default function useEmailData(interval = 2 * 60 * 1000) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const timerRef = useRef(null);

  //maintains flatlist growth without duplicates
  function mergeNewEmails(existing, incoming) {
    const ids = new Set(existing.map(e => e.id));
    const unique = (incoming || []).filter(e => !ids.has(e.id));
    return [...unique, ...existing];
  }

  //accesses flask endpoint for most recent emails
  const fetchEmails = async () => {
    setLoading(true);
    try {
      const resp = await fetch('http://localhost:5000/scan/list', {
        credentials: 'include',
      });
      if (!resp.ok) throw new Error('Network response was not ok');
      const result = await resp.json();
      setData(prev => mergeNewEmails(prev, result.messages || []));
    } catch (err) {
      console.error('Fetch operation failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const searchEmails = async ({
    sender,
    subject,
    customQuery,
    startDate,
    endDate,
    hasAttachment,
  }) => {
    setLoading(true);
    try {
      //replace - with / to work with backend properly
      const formattedStart = startDate ? startDate.replace(/-/g, '/') : undefined;
      const formattedEnd = endDate ? endDate.replace(/-/g, '/') : undefined;

      const body = {
        sender: sender || undefined,
        subject: subject || undefined,
        custom_query_part: customQuery || undefined,
        start_date: formattedStart,
        end_date: formattedEnd,
        has_attachment: hasAttachment || undefined,
      };
      
      //accesses flask endpoint for searching, posts search query data to backend
      const resp = await fetch('http://localhost:5000/scan/search', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!resp.ok) throw new Error('Network response was not ok');
      const result = await resp.json();
      setData(prev => mergeNewEmails(prev, result.messages || []));
    } catch (err) {
      console.error('Search operation failed:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmails();
    timerRef.current = setInterval(fetchEmails, interval);
    return () => clearInterval(timerRef.current);
  }, [interval]);

  return { data, loading, searchEmails };
}
