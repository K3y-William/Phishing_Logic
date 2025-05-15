import pytest
import json
import os
from unittest.mock import patch, MagicMock

import email_reader  # Replace with your actual module name if different


@pytest.fixture
def fake_credentials():
    creds = MagicMock()
    creds.valid = True
    return creds


def test_authenticate_with_valid_token_file(tmp_path):
    token_path = tmp_path / "token.json"
    token_path.write_text(json.dumps({
        "token": "test",
        "refresh_token": "test",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "test.apps.googleusercontent.com",
        "client_secret": "test",
        "scopes": email_reader.SCOPES
    }))

    with patch("email_reader.TOKEN_PATH", str(token_path)):
        with patch("email_reader.CREDENTIALS_PATH", str(token_path)):
            with patch("email_reader.build") as mock_build:
                mock_build.return_value = MagicMock()
                service = email_reader.authenticate_gmail()
                assert service is not None
                mock_build.assert_called_once()


def test_authenticate_with_invalid_token(tmp_path):
    token_path = tmp_path / "token.json"
    token_path.write_text("invalid-json")

    with patch("email_reader.TOKEN_PATH", str(token_path)):
        with patch("email_reader.CREDENTIALS_PATH", str(token_path)):
            with patch("email_reader.build") as mock_build:
                with patch("email_reader.InstalledAppFlow.from_client_secrets_file") as mock_flow:
                    mock_flow.return_value.run_local_server.return_value = MagicMock(valid=True)
                    service = email_reader.authenticate_gmail()
                    assert service is not None
                    mock_build.assert_called_once()


def test_list_inbox_messages_no_messages():
    service = MagicMock()
    service.users().messages().list().execute.return_value = {"messages": []}
    result = email_reader.list_inbox_messages_most_recent(service)
    assert result == []


def test_list_inbox_messages_some_messages():
    mock_message_ids = [{'id': '123'}, {'id': '456'}]
    service = MagicMock()
    service.users().messages().list().execute.return_value = {'messages': mock_message_ids}

    with patch("email_reader.get_message_details") as mock_get_msg:
        mock_get_msg.side_effect = lambda service, msg_id: {
            'id': msg_id,
            'subject': 'Test',
            'from': 'sender@example.com',
            'date': 'Today',
            'snippet': 'Hello',
            'body': 'Body text'
        }
        result = email_reader.list_inbox_messages_most_recent(service)
        assert len(result) == 2
        assert result[0]['id'] == '123'


def test_get_message_details_simple_body():
    service = MagicMock()
    encoded = "SGVsbG8gd29ybGQ="  # base64 of 'Hello world'

    service.users().messages().get().execute.return_value = {
        'id': 'abc',
        'payload': {
            'headers': [
                {'name': 'Subject', 'value': 'Test Subject'},
                {'name': 'From', 'value': 'tester@example.com'},
                {'name': 'Date', 'value': 'Today'}
            ],
            'body': {'data': encoded}
        },
        'snippet': 'snippet text'
    }

    result = email_reader.get_message_details(service, 'abc')
    assert result['subject'] == 'Test Subject'
    assert result['from'] == 'tester@example.com'
    assert 'Hello world' in result['body']


def test_get_message_details_with_parts_text_plain():
    service = MagicMock()
    encoded = "VGV4dCBib2R5"  # base64 of 'Text body'

    service.users().messages().get().execute.return_value = {
        'id': 'abc',
        'payload': {
            'headers': [],
            'parts': [{
                'mimeType': 'text/plain',
                'body': {'data': encoded}
            }]
        },
        'snippet': 'snippet text'
    }

    result = email_reader.get_message_details(service, 'abc')
    assert 'Text body' in result['body']


def test_get_message_details_fallback_nested_parts():
    service = MagicMock()
    encoded = "RkFMTEJBQ0s="  # base64 of 'FALLBACK'

    service.users().messages().get().execute.return_value = {
        'id': 'xyz',
        'payload': {
            'headers': [],
            'parts': [{
                'parts': [{
                    'body': {'data': encoded}
                }]
            }]
        },
        'snippet': 'snippet text'
    }

    result = email_reader.get_message_details(service, 'xyz')
    assert 'FALLBACK' in result['body']


def test_get_message_details_no_body_found():
    service = MagicMock()
    service.users().messages().get().execute.return_value = {
        'id': 'abc',
        'payload': {
            'headers': [],
            'parts': []
        },
        'snippet': 'snippet text'
    }

    result = email_reader.get_message_details(service, 'abc')
    assert result['body'] == ''


def test_get_message_details_http_error():
    service = MagicMock()
    service.users().messages().get().execute.side_effect = Exception("Mock error")

    result = email_reader.get_message_details(service, 'fail')
    assert result is None


def test_list_inbox_messages_exception():
    service = MagicMock()
    service.users().messages().list.side_effect = Exception("Boom")
    result = email_reader.list_inbox_messages_most_recent(service)
    assert result == []

