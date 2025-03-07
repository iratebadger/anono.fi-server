package binmanager

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMessageCreation(t *testing.T) {
	// Test creating a new message
	binID := uint64(0x1000)
	messageID := "test-message-id"
	ciphertext := []byte("encrypted-data")
	
	msg := NewMessage(binID, messageID, ciphertext)
	
	// Check fields
	if msg.BinID != binID {
		t.Errorf("Message binID incorrect: got %X, want %X", msg.BinID, binID)
	}
	
	if msg.MessageID != messageID {
		t.Errorf("Message ID incorrect: got %s, want %s", msg.MessageID, messageID)
	}
	
	if string(msg.Ciphertext) != string(ciphertext) {
		t.Errorf("Message ciphertext incorrect: got %s, want %s", 
		         string(msg.Ciphertext), string(ciphertext))
	}
	
	// Timestamp should be zero initially
	if !msg.Timestamp.IsZero() {
		t.Errorf("New message should have zero timestamp, got %v", msg.Timestamp)
	}
}

func TestMessageJSONMarshaling(t *testing.T) {
	// Create a message with all fields set
	msg := &Message{
		BinID:      0x1000,
		MessageID:  "test-msg-id",
		Ciphertext: []byte("test-data"),
		Timestamp:  time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	
	// Marshal to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}
	
	// Unmarshal back to a new message
	var decodedMsg Message
	err = json.Unmarshal(data, &decodedMsg)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}
	
	// Check all fields match
	if decodedMsg.BinID != msg.BinID {
		t.Errorf("BinID doesn't match after JSON roundtrip: got %X, want %X", 
		         decodedMsg.BinID, msg.BinID)
	}
	
	if decodedMsg.MessageID != msg.MessageID {
		t.Errorf("MessageID doesn't match after JSON roundtrip: got %s, want %s", 
		         decodedMsg.MessageID, msg.MessageID)
	}
	
	if string(decodedMsg.Ciphertext) != string(msg.Ciphertext) {
		t.Errorf("Ciphertext doesn't match after JSON roundtrip: got %s, want %s", 
		         string(decodedMsg.Ciphertext), string(msg.Ciphertext))
	}
	
	if !decodedMsg.Timestamp.Equal(msg.Timestamp) {
		t.Errorf("Timestamp doesn't match after JSON roundtrip: got %v, want %v", 
		         decodedMsg.Timestamp, msg.Timestamp)
	}
	
	// Test with zero timestamp (should be omitted in JSON)
	msg.Timestamp = time.Time{}
	data, err = json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal message with zero timestamp: %v", err)
	}
	
	// Check JSON doesn't contain timestamp field
	if string(data) != `{"bin_id":4096,"message_id":"test-msg-id","ciphertext":"dGVzdC1kYXRh"}` {
		t.Errorf("JSON for message with zero timestamp is incorrect: %s", string(data))
	}
	
	// Test unmarshaling with missing timestamp
	var decodedMsg2 Message
	err = json.Unmarshal(data, &decodedMsg2)
	if err != nil {
		t.Fatalf("Failed to unmarshal message without timestamp: %v", err)
	}
	
	// Timestamp should be zero
	if !decodedMsg2.Timestamp.IsZero() {
		t.Errorf("Timestamp should be zero after unmarshaling without timestamp field, got %v", 
		         decodedMsg2.Timestamp)
	}
}

func TestMessageTimestampFormatting(t *testing.T) {
	// Create a message with a specific timestamp
	timestamp := time.Date(2023, 1, 1, 12, 34, 56, 789000000, time.UTC)
	msg := &Message{
		BinID:      0x1000,
		MessageID:  "test-msg-id",
		Ciphertext: []byte("test-data"),
		Timestamp:  timestamp,
	}
	
	// Marshal to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}
	
	// Check the timestamp format in JSON (RFC3339Nano)
	expectedTimestampJSON := `"timestamp":"2023-01-01T12:34:56.789Z"`
	if string(data) != `{"bin_id":4096,"message_id":"test-msg-id","ciphertext":"dGVzdC1kYXRh",` + expectedTimestampJSON + `}` {
		t.Errorf("Timestamp format in JSON is incorrect: %s", string(data))
	}
	
	// Unmarshal from JSON with different timestamp format
	jsonWithDifferentFormat := `{"bin_id":4096,"message_id":"test-msg-id","ciphertext":"dGVzdC1kYXRh","timestamp":"2023-01-01T12:34:56Z"}`
	var decodedMsg Message
	err = json.Unmarshal([]byte(jsonWithDifferentFormat), &decodedMsg)
	if err != nil {
		t.Fatalf("Failed to unmarshal message with different timestamp format: %v", err)
	}
	
	// Check timestamp was parsed correctly (should be without nanoseconds)
	expectedTimestamp := time.Date(2023, 1, 1, 12, 34, 56, 0, time.UTC)
	if !decodedMsg.Timestamp.Equal(expectedTimestamp) {
		t.Errorf("Parsed timestamp incorrect: got %v, want %v", 
		         decodedMsg.Timestamp, expectedTimestamp)
	}
}

func TestMessageJSONUnmarshalingErrors(t *testing.T) {
	// Test unmarshaling with invalid timestamp
	invalidJSON := `{"bin_id":4096,"message_id":"test-msg-id","ciphertext":"dGVzdC1kYXRh","timestamp":"invalid-date"}`
	var msg Message
	err := json.Unmarshal([]byte(invalidJSON), &msg)
	if err == nil {
		t.Error("Expected error when unmarshaling invalid timestamp, got nil")
	}
	
	// Test unmarshaling with invalid JSON
	invalidJSON = `{"bin_id":4096,"message_id":"test-msg-id","ciphertext":"dGVzdC1kYXRh",timestamp:"2023-01-01T12:34:56Z"}`
	err = json.Unmarshal([]byte(invalidJSON), &msg)
	if err == nil {
		t.Error("Expected error when unmarshaling invalid JSON, got nil")
	}
}