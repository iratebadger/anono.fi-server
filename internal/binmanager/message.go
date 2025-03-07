package binmanager

import (
	"encoding/json"
	"time"
)

// Message represents a message in the system
type Message struct {
	BinID      uint64    `json:"bin_id"`
	MessageID  string    `json:"message_id"`
	Ciphertext []byte    `json:"ciphertext"`
	Timestamp  time.Time `json:"timestamp,omitempty"` // Server-side only, not sent to clients
}

// NewMessage creates a new message
func NewMessage(binID uint64, messageID string, ciphertext []byte) *Message {
	return &Message{
		BinID:      binID,
		MessageID:  messageID,
		Ciphertext: ciphertext,
	}
}

// MarshalJSON implements json.Marshaler interface
// Ensures we don't expose the Timestamp field to clients
func (m *Message) MarshalJSON() ([]byte, error) {
	type Alias Message
	return json.Marshal(&struct {
		*Alias
		Timestamp string `json:"timestamp,omitempty"`
	}{
		Alias: (*Alias)(m),
		// Only include timestamp if it's not zero
		Timestamp: func() string {
			if m.Timestamp.IsZero() {
				return ""
			}
			return m.Timestamp.Format(time.RFC3339Nano)
		}(),
	})
}

// UnmarshalJSON implements json.Unmarshaler interface
func (m *Message) UnmarshalJSON(data []byte) error {
	type Alias Message
	aux := &struct {
		*Alias
		Timestamp string `json:"timestamp,omitempty"`
	}{
		Alias: (*Alias)(m),
	}
	
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	
	if aux.Timestamp != "" {
		ts, err := time.Parse(time.RFC3339Nano, aux.Timestamp)
		if err != nil {
			return err
		}
		m.Timestamp = ts
	}
	
	return nil
}