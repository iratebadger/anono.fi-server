package binmanager

import (
	"sync"
	"testing"
	"time"
)

func TestBinBasicOperations(t *testing.T) {
	bin := NewBin(0x1000)
	
	// Check initial state
	if bin.ID != 0x1000 {
		t.Errorf("Bin ID incorrect: got %X, want %X", bin.ID, 0x1000)
	}
	
	if len(bin.Messages) != 0 {
		t.Errorf("New bin should have no messages, got %d", len(bin.Messages))
	}
	
	if len(bin.Clients) != 0 {
		t.Errorf("New bin should have no clients, got %d", len(bin.Clients))
	}
	
	// Add a message
	msg := &Message{
		BinID:      0x1000,
		MessageID:  "test-message",
		Ciphertext: []byte("data"),
		Timestamp:  time.Now(),
	}
	
	bin.AddMessage(msg)
	
	// Check message was added
	if len(bin.Messages) != 1 {
		t.Fatalf("Bin should have 1 message after adding, got %d", len(bin.Messages))
	}
	
	if bin.Messages[0].MessageID != "test-message" {
		t.Errorf("Message ID incorrect: got %s, want %s", bin.Messages[0].MessageID, "test-message")
	}
	
	// Add a client
	client := NewMockClient()
	bin.AddClient("client1", client)
	
	// Check client was added
	if len(bin.Clients) != 1 {
		t.Fatalf("Bin should have 1 client after adding, got %d", len(bin.Clients))
	}
	
	// Remove the client
	bin.RemoveClient("client1")
	
	// Check client was removed
	if len(bin.Clients) != 0 {
		t.Errorf("Bin should have no clients after removal, got %d", len(bin.Clients))
	}
}

func TestBinGetRecentMessages(t *testing.T) {
	bin := NewBin(0x1000)
	
	// Add messages with different timestamps
	now := time.Now()
	
	oldMsg := &Message{
		BinID:      0x1000,
		MessageID:  "old-message",
		Ciphertext: []byte("old-data"),
		Timestamp:  now.Add(-2 * time.Hour),
	}
	
	recentMsg := &Message{
		BinID:      0x1000,
		MessageID:  "recent-message",
		Ciphertext: []byte("recent-data"),
		Timestamp:  now.Add(-30 * time.Minute),
	}
	
	veryRecentMsg := &Message{
		BinID:      0x1000,
		MessageID:  "very-recent-message",
		Ciphertext: []byte("very-recent-data"),
		Timestamp:  now,
	}
	
	bin.AddMessage(oldMsg)
	bin.AddMessage(recentMsg)
	bin.AddMessage(veryRecentMsg)
	
	// Get messages with 1 hour retention
	messages := bin.GetRecentMessages(1 * time.Hour)
	
	// Should get 2 messages (recent and very recent, but not old)
	if len(messages) != 2 {
		t.Fatalf("Expected 2 recent messages, got %d", len(messages))
	}
	
	// Check we got the right messages
	foundRecent := false
	foundVeryRecent := false
	
	for _, msg := range messages {
		if msg.MessageID == "recent-message" {
			foundRecent = true
		}
		if msg.MessageID == "very-recent-message" {
			foundVeryRecent = true
		}
		if msg.MessageID == "old-message" {
			t.Error("Old message should not be included in recent messages")
		}
	}
	
	if !foundRecent || !foundVeryRecent {
		t.Errorf("Some recent messages were missing: foundRecent=%v, foundVeryRecent=%v", 
		         foundRecent, foundVeryRecent)
	}
}

func TestBinRemoveMessagesBefore(t *testing.T) {
	bin := NewBin(0x1000)
	
	// Add messages with different timestamps
	now := time.Now()
	
	msg1 := &Message{
		BinID:      0x1000,
		MessageID:  "msg1",
		Ciphertext: []byte("data1"),
		Timestamp:  now.Add(-3 * time.Hour),
	}
	
	msg2 := &Message{
		BinID:      0x1000,
		MessageID:  "msg2",
		Ciphertext: []byte("data2"),
		Timestamp:  now.Add(-2 * time.Hour),
	}
	
	msg3 := &Message{
		BinID:      0x1000,
		MessageID:  "msg3",
		Ciphertext: []byte("data3"),
		Timestamp:  now.Add(-1 * time.Hour),
	}
	
	msg4 := &Message{
		BinID:      0x1000,
		MessageID:  "msg4",
		Ciphertext: []byte("data4"),
		Timestamp:  now,
	}
	
	bin.AddMessage(msg1)
	bin.AddMessage(msg2)
	bin.AddMessage(msg3)
	bin.AddMessage(msg4)
	
	// Remove messages older than 90 minutes ago
	cutoff := now.Add(-90 * time.Minute)
	bin.RemoveMessagesBefore(cutoff)
	
	// Should have 2 messages left (msg3 and msg4)
	if len(bin.Messages) != 2 {
		t.Fatalf("Expected 2 messages after removal, got %d", len(bin.Messages))
	}
	
	// Check we have the right messages
	if bin.Messages[0].MessageID != "msg3" || bin.Messages[1].MessageID != "msg4" {
		t.Errorf("Incorrect messages after removal: %v", bin.Messages)
	}
	
	// Remove all messages
	bin.RemoveMessagesBefore(now.Add(1 * time.Hour))
	
	// Should have 0 messages left
	if len(bin.Messages) != 0 {
		t.Errorf("Expected 0 messages after removal, got %d", len(bin.Messages))
	}
}

func TestBinBroadcastMessage(t *testing.T) {
	bin := NewBin(0x1000)
	
	// Add multiple clients
	numClients := 5
	clients := make([]*MockClient, numClients)
	
	for i := 0; i < numClients; i++ {
		clients[i] = NewMockClient()
		bin.AddClient("client"+string(rune(i)), clients[i])
	}
	
	// Broadcast a message
	msg := &Message{
		BinID:      0x1000,
		MessageID:  "broadcast-test",
		Ciphertext: []byte("broadcast-data"),
	}
	
	bin.BroadcastMessage(msg)
	
	// Give some time for delivery
	time.Sleep(10 * time.Millisecond)
	
	// Check all clients received the message
	for i, client := range clients {
		messages := client.GetMessages()
		
		if len(messages) != 1 {
			t.Errorf("Client %d should have received 1 message, got %d", i, len(messages))
			continue
		}
		
		if messages[0].MessageID != "broadcast-test" {
			t.Errorf("Client %d received wrong message: got %s, want %s", 
			         i, messages[0].MessageID, "broadcast-test")
		}
	}
	
	// Test broadcasting to a disconnected client
	disconnectedClient := NewMockClient()
	bin.AddClient("disconnected", disconnectedClient)
	disconnectedClient.Close()
	
	// Broadcast another message
	msg2 := &Message{
		BinID:      0x1000,
		MessageID:  "broadcast-test-2",
		Ciphertext: []byte("broadcast-data-2"),
	}
	
	bin.BroadcastMessage(msg2)
	
	// The disconnected client should be removed automatically
	if _, exists := bin.Clients["disconnected"]; exists {
		t.Error("Disconnected client should have been removed")
	}
}

func TestBinMergeFrom(t *testing.T) {
	bin1 := NewBin(0x1000)
	bin2 := NewBin(0x2000)
	
	// Add messages to both bins
	msg1 := &Message{
		BinID:      0x1000,
		MessageID:  "msg1",
		Ciphertext: []byte("data1"),
		Timestamp:  time.Now().Add(-1 * time.Hour),
	}
	
	msg2 := &Message{
		BinID:      0x2000,
		MessageID:  "msg2",
		Ciphertext: []byte("data2"),
		Timestamp:  time.Now(),
	}
	
	bin1.AddMessage(msg1)
	bin2.AddMessage(msg2)
	
	// Add clients to both bins
	client1 := NewMockClient()
	client2 := NewMockClient()
	
	bin1.AddClient("client1", client1)
	bin2.AddClient("client2", client2)
	
	// Merge bin2 into bin1
	bin1.mergeFrom(bin2)
	
	// Check messages were merged
	if len(bin1.Messages) != 2 {
		t.Errorf("After merge, bin1 should have 2 messages, got %d", len(bin1.Messages))
	}
	
	foundMsg1 := false
	foundMsg2 := false
	
	for _, msg := range bin1.Messages {
		if msg.MessageID == "msg1" {
			foundMsg1 = true
		}
		if msg.MessageID == "msg2" {
			foundMsg2 = true
		}
	}
	
	if !foundMsg1 || !foundMsg2 {
		t.Errorf("After merge, bin1 should contain both messages: foundMsg1=%v, foundMsg2=%v", 
		         foundMsg1, foundMsg2)
	}
	
	// Check clients were merged
	if len(bin1.Clients) != 2 {
		t.Errorf("After merge, bin1 should have 2 clients, got %d", len(bin1.Clients))
	}
	
	if _, exists := bin1.Clients["client1"]; !exists {
		t.Error("After merge, client1 is missing from bin1")
	}
	
	if _, exists := bin1.Clients["client2"]; !exists {
		t.Error("After merge, client2 is missing from bin1")
	}
}

func TestBinConcurrency(t *testing.T) {
	bin := NewBin(0x1000)
	
	// Test concurrent message adding
	numMessages := 100
	var wg sync.WaitGroup
	
	for i := 0; i < numMessages; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			msg := &Message{
				BinID:      0x1000,
				MessageID:  "msg" + string(rune(idx)),
				Ciphertext: []byte("data" + string(rune(idx))),
				Timestamp:  time.Now(),
			}
			bin.AddMessage(msg)
		}(i)
	}
	
	wg.Wait()
	
	if len(bin.Messages) != numMessages {
		t.Errorf("Expected %d messages after concurrent adds, got %d", numMessages, len(bin.Messages))
	}
	
	// Test concurrent client management
	numClients := 100
	clients := make([]*MockClient, numClients)
	
	for i := 0; i < numClients; i++ {
		clients[i] = NewMockClient()
	}
	
	wg = sync.WaitGroup{}
	
	// Add clients concurrently
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bin.AddClient("client"+string(rune(idx)), clients[idx])
		}(i)
	}
	
	wg.Wait()
	
	if len(bin.Clients) != numClients {
		t.Errorf("Expected %d clients after concurrent adds, got %d", numClients, len(bin.Clients))
	}
	
	// Remove clients concurrently
	wg = sync.WaitGroup{}
	
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			bin.RemoveClient("client" + string(rune(idx)))
		}(i)
	}
	
	wg.Wait()
	
	if len(bin.Clients) != 0 {
		t.Errorf("Expected 0 clients after concurrent removes, got %d", len(bin.Clients))
	}
}