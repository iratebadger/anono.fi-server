package binmanager

import (
	"sync"
	"testing"
	"time"
)

// MockClient implements the Client interface for testing
type MockClient struct {
	messages []*Message
	mu       sync.Mutex
	closed   bool
}

func NewMockClient() *MockClient {
	return &MockClient{
		messages: make([]*Message, 0),
	}
}

func (c *MockClient) SendMessage(msg *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.messages = append(c.messages, msg)
	return nil
}

func (c *MockClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
}

func (c *MockClient) GetMessages() []*Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]*Message, len(c.messages))
	copy(result, c.messages)
	return result
}

func TestBinManagerBasicFunctionality(t *testing.T) {
	// Create a bin manager with a 12-bit mask (4096 bins) and 1-hour retention
	mask := uint64(0xFFFFFFFFFFFFF000)
	retention := 1 * time.Hour
	manager := NewBinManager(mask, retention)

	// Test GetBinID
	channelID := uint64(0x1234567890ABCDEF)
	expectedBinID := channelID & mask
	binID := manager.GetBinID(channelID)
	
	if binID != expectedBinID {
		t.Errorf("GetBinID returned incorrect bin ID: got %X, want %X", binID, expectedBinID)
	}

	// Test GetCurrentMask
	if manager.GetCurrentMask() != mask {
		t.Errorf("GetCurrentMask returned incorrect mask: got %X, want %X", manager.GetCurrentMask(), mask)
	}

	// Test message storage and retrieval
	testMessage := &Message{
		BinID:      expectedBinID,
		MessageID:  "test-message-1",
		Ciphertext: []byte("encrypted-data"),
	}

	// Add the message
	manager.AddMessage(testMessage)

	// Retrieve recent messages
	messages := manager.GetRecentMessages(expectedBinID)
	
	if len(messages) != 1 {
		t.Fatalf("GetRecentMessages returned incorrect number of messages: got %d, want 1", len(messages))
	}
	
	if messages[0].MessageID != testMessage.MessageID {
		t.Errorf("Retrieved message has incorrect ID: got %s, want %s", messages[0].MessageID, testMessage.MessageID)
	}

	// Test a non-existent bin
	nonExistentBinID := uint64(0xAAAAAAAAAAAAAA000)
	messages = manager.GetRecentMessages(nonExistentBinID)
	
	if len(messages) != 0 {
		t.Errorf("GetRecentMessages for non-existent bin should return empty slice, got %d messages", len(messages))
	}
}

func TestBinManagerSubscription(t *testing.T) {
	// Create a bin manager
	mask := uint64(0xFFFFFFFFFFFFF000)
	retention := 1 * time.Hour
	manager := NewBinManager(mask, retention)

	// Create some test bins and clients
	bin1 := uint64(0x1000)
	bin2 := uint64(0x2000)
	
	client1 := NewMockClient()
	client2 := NewMockClient()
	client3 := NewMockClient()

	// Subscribe clients to bins
	manager.Subscribe(bin1, "client1", client1)
	manager.Subscribe(bin1, "client2", client2)
	manager.Subscribe(bin2, "client3", client3)

	// Add messages to bins
	msg1 := &Message{
		BinID:      bin1,
		MessageID:  "msg1",
		Ciphertext: []byte("data1"),
	}
	
	msg2 := &Message{
		BinID:      bin2,
		MessageID:  "msg2",
		Ciphertext: []byte("data2"),
	}

	manager.AddMessage(msg1)
	manager.AddMessage(msg2)

	// Give some time for message delivery
	time.Sleep(10 * time.Millisecond)

	// Check client1 received msg1 but not msg2
	client1Messages := client1.GetMessages()
	if len(client1Messages) != 1 || client1Messages[0].MessageID != "msg1" {
		t.Errorf("Client1 received incorrect messages: %v", client1Messages)
	}

	// Check client2 received msg1 but not msg2
	client2Messages := client2.GetMessages()
	if len(client2Messages) != 1 || client2Messages[0].MessageID != "msg1" {
		t.Errorf("Client2 received incorrect messages: %v", client2Messages)
	}

	// Check client3 received msg2 but not msg1
	client3Messages := client3.GetMessages()
	if len(client3Messages) != 1 || client3Messages[0].MessageID != "msg2" {
		t.Errorf("Client3 received incorrect messages: %v", client3Messages)
	}

	// Test unsubscribe
	manager.Unsubscribe(bin1, "client1")
	
	// Add another message to bin1
	msg3 := &Message{
		BinID:      bin1,
		MessageID:  "msg3",
		Ciphertext: []byte("data3"),
	}
	
	manager.AddMessage(msg3)
	
	// Give some time for message delivery
	time.Sleep(10 * time.Millisecond)

	// client1 should not receive the new message
	client1Messages = client1.GetMessages()
	if len(client1Messages) != 1 {
		t.Errorf("Client1 should have only 1 message after unsubscribe, got %d", len(client1Messages))
	}

	// client2 should receive the new message
	client2Messages = client2.GetMessages()
	if len(client2Messages) != 2 || client2Messages[1].MessageID != "msg3" {
		t.Errorf("Client2 should have received msg3 after client1 unsubscribed")
	}
}

func TestBinManagerExpandContract(t *testing.T) {
	// Create a bin manager with initial mask
	initialMask := uint64(0xFFFFFFFFFFFFF000) // 12 bits, 4096 bins
	manager := NewBinManager(initialMask, 1*time.Hour)

	// Test ExpandBins
	manager.ExpandBins()
	expandedMask := uint64(0xFFFFFFFFFFFF8000) // Added 1 bit, now 13 bits
	
	if manager.GetCurrentMask() != expandedMask {
		t.Errorf("After ExpandBins, mask should be %X, got %X", expandedMask, manager.GetCurrentMask())
	}

	// Add messages to bins that will be merged when we contract
	bin1 := uint64(0x1000)
	bin2 := uint64(0x9000) // Will merge with bin1 when we contract mask by 1 bit
	
	msg1 := &Message{
		BinID:      bin1,
		MessageID:  "msg1",
		Ciphertext: []byte("data1"),
	}
	
	msg2 := &Message{
		BinID:      bin2,
		MessageID:  "msg2",
		Ciphertext: []byte("data2"),
	}

	manager.AddMessage(msg1)
	manager.AddMessage(msg2)

	// Subscribe clients to both bins
	client1 := NewMockClient()
	client2 := NewMockClient()
	
	manager.Subscribe(bin1, "client1", client1)
	manager.Subscribe(bin2, "client2", client2)

	// Contract bins
	manager.ContractBins()
	
	if manager.GetCurrentMask() != initialMask {
		t.Errorf("After ContractBins, mask should be back to %X, got %X", initialMask, manager.GetCurrentMask())
	}

	// Both messages should now be in the same bin
	messages := manager.GetRecentMessages(bin1)
	
	// We should have both messages in bin1 after contraction
	if len(messages) != 2 {
		t.Errorf("After ContractBins, bin1 should have 2 messages, got %d", len(messages))
	}

	// Both msg1 and msg2 should be in the results
	foundMsg1 := false
	foundMsg2 := false
	
	for _, msg := range messages {
		if msg.MessageID == "msg1" {
			foundMsg1 = true
		}
		if msg.MessageID == "msg2" {
			foundMsg2 = true
		}
	}
	
	if !foundMsg1 || !foundMsg2 {
		t.Errorf("After ContractBins, bin should contain both messages: foundMsg1=%v, foundMsg2=%v", foundMsg1, foundMsg2)
	}
}

func TestBinManagerCleanup(t *testing.T) {
	// Create a bin manager with a short retention for testing
	mask := uint64(0xFFFFFFFFFFFFF000)
	retention := 100 * time.Millisecond
	manager := NewBinManager(mask, retention)

	// Start cleanup service
	manager.StartCleanupService(50 * time.Millisecond)
	defer manager.Stop()

	// Add a message
	bin := uint64(0x1000)
	msg := &Message{
		BinID:      bin,
		MessageID:  "test-message",
		Ciphertext: []byte("data"),
		Timestamp:  time.Now(), // Current time
	}
	
	manager.AddMessage(msg)

	// Verify the message is there
	messages := manager.GetRecentMessages(bin)
	if len(messages) != 1 {
		t.Fatalf("Message not added correctly, got %d messages", len(messages))
	}

	// Wait for the retention period plus a little extra for the cleanup to run
	time.Sleep(retention + 100*time.Millisecond)

	// Verify the message was cleaned up
	messages = manager.GetRecentMessages(bin)
	if len(messages) != 0 {
		t.Errorf("Message should have been cleaned up, but got %d messages", len(messages))
	}
}

func TestBinManagerConcurrency(t *testing.T) {
	// Create a bin manager
	mask := uint64(0xFFFFFFFFFFFFF000)
	retention := 1 * time.Hour
	manager := NewBinManager(mask, retention)

	// Create several bins and clients
	numBins := 10
	numMessagesPerBin := 20
	numClientsPerBin := 5

	var wg sync.WaitGroup

	// For each bin...
	for binIdx := 0; binIdx < numBins; binIdx++ {
		binID := uint64(0x1000 * (binIdx + 1))

		// Create clients and subscribe them
		clients := make([]*MockClient, numClientsPerBin)
		for clientIdx := 0; clientIdx < numClientsPerBin; clientIdx++ {
			clients[clientIdx] = NewMockClient()
			clientID := "client_" + string(rune(binIdx)) + "_" + string(rune(clientIdx))
			manager.Subscribe(binID, clientID, clients[clientIdx])
		}

		// Add messages concurrently
		for msgIdx := 0; msgIdx < numMessagesPerBin; msgIdx++ {
			wg.Add(1)
			go func(bin uint64, idx int) {
				defer wg.Done()
				msg := &Message{
					BinID:      bin,
					MessageID:  "msg_" + string(rune(idx)),
					Ciphertext: []byte("data_" + string(rune(idx))),
				}
				manager.AddMessage(msg)
			}(binID, msgIdx)
		}
	}

	// Wait for all messages to be sent
	wg.Wait()

	// Give some time for message delivery
	time.Sleep(50 * time.Millisecond)

	// Verify each bin has the correct number of messages
	for binIdx := 0; binIdx < numBins; binIdx++ {
		binID := uint64(0x1000 * (binIdx + 1))
		messages := manager.GetRecentMessages(binID)
		
		if len(messages) != numMessagesPerBin {
			t.Errorf("Bin %d should have %d messages, got %d", binIdx, numMessagesPerBin, len(messages))
		}
	}
}

func TestBinManagerGetRetentionHours(t *testing.T) {
	// Test with different retention periods
	testCases := []struct {
		retention time.Duration
		hours     float64
	}{
		{
			retention: 1 * time.Hour,
			hours:     1.0,
		},
		{
			retention: 24 * time.Hour,
			hours:     24.0,
		},
		{
			retention: 30 * time.Minute,
			hours:     0.5,
		},
		{
			retention: 90 * time.Minute,
			hours:     1.5,
		},
	}

	for _, tc := range testCases {
		manager := NewBinManager(0xFFFFFFFFFFFFF000, tc.retention)
		
		hours := manager.GetRetentionHours()
		if hours != tc.hours {
			t.Errorf("GetRetentionHours returned incorrect value: got %f, want %f", hours, tc.hours)
		}
	}
}

func TestBinManagerMultipleExpand(t *testing.T) {
	// Create a bin manager with initial mask
	initialMask := uint64(0xFFFFFFFFFFFFF000) // 12 bits, 4096 bins
	manager := NewBinManager(initialMask, 1*time.Hour)

	// Test multiple expands
	masks := []uint64{
		0xFFFFFFFFFFFF8000, // First expand (13 bits)
		0xFFFFFFFFFFFFC000, // Second expand (14 bits)
		0xFFFFFFFFFFFFE000, // Third expand (15 bits)
		0xFFFFFFFFFFFFF000, // Fourth expand (16 bits)
	}

	for i, expectedMask := range masks {
		manager.ExpandBins()
		actualMask := manager.GetCurrentMask()
		
		if actualMask != expectedMask {
			t.Errorf("After expand #%d, mask should be %X, got %X", i+1, expectedMask, actualMask)
		}
	}
}

func TestBinManagerMultipleContract(t *testing.T) {
	// Create a bin manager with expanded mask (16 bits)
	expandedMask := uint64(0xFFFFFFFFFFFF0000)
	manager := NewBinManager(expandedMask, 1*time.Hour)

	// Test multiple contracts
	masks := []uint64{
		0xFFFFFFFFFFFFF000, // First contract (15 bits)
		0xFFFFFFFFFFFFE000, // Second contract (14 bits)
		0xFFFFFFFFFFFFC000, // Third contract (13 bits)
		0xFFFFFFFFFFFF8000, // Fourth contract (12 bits)
	}

	for i, expectedMask := range masks {
		manager.ContractBins()
		actualMask := manager.GetCurrentMask()
		
		if actualMask != expectedMask {
			t.Errorf("After contract #%d, mask should be %X, got %X", i+1, expectedMask, actualMask)
		}
	}
}

func TestBinManagerEdgeCases(t *testing.T) {
	// Test with extremely small mask
	smallMask := uint64(0x0000000000000001) // Just 1 bit
	manager := NewBinManager(smallMask, 1*time.Hour)
	
	// Adding messages to different bins should all go to the same bin due to the mask
	bin1 := uint64(0x0000000000000001)
	bin2 := uint64(0x0000000000000003) // Will map to 0x0000000000000001 with mask
	
	msg1 := &Message{
		BinID:      bin1,
		MessageID:  "msg1",
		Ciphertext: []byte("data1"),
	}
	
	msg2 := &Message{
		BinID:      bin2,
		MessageID:  "msg2",
		Ciphertext: []byte("data2"),
	}
	
	manager.AddMessage(msg1)
	manager.AddMessage(msg2)
	
	// Both messages should be in the same bin
	messages := manager.GetRecentMessages(bin1)
	
	if len(messages) != 2 {
		t.Errorf("With small mask, both messages should be in the same bin, got %d messages", len(messages))
	}
	
	// Test contract with smallest possible mask (should not go below 1 bit)
	manager.ContractBins()
	
	if manager.GetCurrentMask() != smallMask {
		t.Errorf("Should not be able to contract below smallest mask, got %X", manager.GetCurrentMask())
	}
	
	// Test with extremely large mask
	largeMask := uint64(0xFFFFFFFFFFFFFFFF) // All bits set
	manager = NewBinManager(largeMask, 1*time.Hour)
	
	// Should not be able to expand beyond maximum mask
	manager.ExpandBins()
	
	if manager.GetCurrentMask() != largeMask {
		t.Errorf("Should not be able to expand beyond maximum mask, got %X", manager.GetCurrentMask())
	}
}