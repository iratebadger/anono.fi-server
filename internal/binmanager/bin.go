package binmanager

import (
	"sync"
	"time"
)

// Client interface represents a connected client that can receive messages
type Client interface {
	SendMessage(*Message) error
}

// Bin represents a message bin that clients can subscribe to
type Bin struct {
	ID       uint64
	Messages []*Message
	Clients  map[string]Client
	msgMutex sync.RWMutex
	clMutex  sync.RWMutex
}

// NewBin creates a new message bin
func NewBin(id uint64) *Bin {
	return &Bin{
		ID:       id,
		Messages: make([]*Message, 0, 100),
		Clients:  make(map[string]Client),
	}
}

// AddMessage adds a message to the bin
func (b *Bin) AddMessage(msg *Message) {
	b.msgMutex.Lock()
	defer b.msgMutex.Unlock()
	
	b.Messages = append(b.Messages, msg)
}

// GetRecentMessages returns messages newer than the cutoff time
func (b *Bin) GetRecentMessages(retention time.Duration) []*Message {
	b.msgMutex.RLock()
	defer b.msgMutex.RUnlock()
	
	cutoff := time.Now().Add(-retention)
	result := make([]*Message, 0)
	
	// Find messages newer than cutoff
	for _, msg := range b.Messages {
		if msg.Timestamp.After(cutoff) {
			result = append(result, msg)
		}
	}
	
	return result
}

// RemoveMessagesBefore removes messages older than the specified time
func (b *Bin) RemoveMessagesBefore(cutoff time.Time) {
	b.msgMutex.Lock()
	defer b.msgMutex.Unlock()
	
	// Find index of first message newer than cutoff
	idx := 0
	for i, msg := range b.Messages {
		if msg.Timestamp.After(cutoff) {
			idx = i
			break
		}
	}
	
	// If all messages are newer than cutoff, idx will be 0
	// If all messages are older than cutoff, idx will be len(b.Messages)
	if idx > 0 {
		// Remove all messages before idx
		b.Messages = b.Messages[idx:]
	}
}

// AddClient adds a client to the bin's subscribers
func (b *Bin) AddClient(clientID string, client Client) {
	b.clMutex.Lock()
	defer b.clMutex.Unlock()
	
	b.Clients[clientID] = client
}

// RemoveClient removes a client from the bin's subscribers
func (b *Bin) RemoveClient(clientID string) {
	b.clMutex.Lock()
	defer b.clMutex.Unlock()
	
	delete(b.Clients, clientID)
}

// BroadcastMessage sends a message to all subscribed clients
func (b *Bin) BroadcastMessage(msg *Message) {
	b.clMutex.RLock()
	clients := make(map[string]Client, len(b.Clients))
	for id, client := range b.Clients {
		clients[id] = client
	}
	b.clMutex.RUnlock()
	
	// Send to each client concurrently
	var wg sync.WaitGroup
	for id, client := range clients {
		wg.Add(1)
		go func(cid string, c Client) {
			defer wg.Done()
			err := c.SendMessage(msg)
			if err != nil {
				// Client might have disconnected
				b.RemoveClient(cid)
			}
		}(id, client)
	}
	
	wg.Wait()
}

// mergeFrom merges messages and clients from another bin
func (b *Bin) mergeFrom(other *Bin) {
	// Merge messages
	b.msgMutex.Lock()
	other.msgMutex.RLock()
	b.Messages = append(b.Messages, other.Messages...)
	other.msgMutex.RUnlock()
	b.msgMutex.Unlock()
	
	// Merge clients
	b.clMutex.Lock()
	other.clMutex.RLock()
	for id, client := range other.Clients {
		b.Clients[id] = client
	}
	other.clMutex.RUnlock()
	b.clMutex.Unlock()
}