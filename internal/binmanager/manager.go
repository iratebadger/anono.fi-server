package binmanager

import (
	"sync"
	"time"
)

// BinManager handles the routing and storage of messages in bins
type BinManager struct {
	bins           map[uint64]*Bin
	mutex          sync.RWMutex
	currentMask    uint64
	retention      time.Duration
	cleanupTicker  *time.Ticker
	cleanupDone    chan struct{}
}

// NewBinManager creates a new bin manager with the specified initial mask and message retention period
func NewBinManager(initialMask uint64, retention time.Duration) *BinManager {
	return &BinManager{
		bins:        make(map[uint64]*Bin),
		currentMask: initialMask,
		retention:   retention,
		cleanupDone: make(chan struct{}),
	}
}

// GetBinID calculates the bin ID from a channel ID using the current mask
func (bm *BinManager) GetBinID(channelID uint64) uint64 {
	return channelID & bm.currentMask
}

// GetCurrentMask returns the current bin mask
func (bm *BinManager) GetCurrentMask() uint64 {
	bm.mutex.RLock()
	defer bm.mutex.RUnlock()
	return bm.currentMask
}

// GetRetentionHours returns the message retention period in hours
func (bm *BinManager) GetRetentionHours() float64 {
	return bm.retention.Hours()
}

// ExpandBins increases the number of bins by adding a new bit to the mask
func (bm *BinManager) ExpandBins() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	
	// Find lowest unset bit in mask
	newBit := uint64(1)
	for (bm.currentMask & newBit) != 0 && newBit != 0 {
		newBit <<= 1
	}
	
	if newBit == 0 {
		// All bits are set, can't expand further
		return
	}
	
	// Add the new bit to the mask
	bm.currentMask |= newBit
}

// ContractBins reduces the number of bins by removing a bit from the mask
func (bm *BinManager) ContractBins() {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()
	
	// Find lowest set bit in mask
	lowestBit := uint64(1)
	for (bm.currentMask & lowestBit) == 0 && lowestBit != 0 {
		lowestBit <<= 1
	}
	
	if lowestBit == 0 || bm.currentMask == lowestBit {
		// No bits set or only one bit set, can't contract further
		return
	}
	
	// Clear the lowest bit from the mask
	newMask := bm.currentMask &^ lowestBit
	
	// Merge bins according to new mask
	newBins := make(map[uint64]*Bin)
	for binID, bin := range bm.bins {
		newBinID := binID & newMask
		if existingBin, exists := newBins[newBinID]; exists {
			// Merge bins
			existingBin.mergeFrom(bin)
		} else {
			// Just rekey
			newBins[newBinID] = bin
		}
	}
	
	bm.bins = newBins
	bm.currentMask = newMask
}

// AddMessage adds a message to the appropriate bin and broadcasts it to subscribers
func (bm *BinManager) AddMessage(msg *Message) {
	binID := msg.BinID
	
	bm.mutex.RLock()
	bin, exists := bm.bins[binID]
	bm.mutex.RUnlock()
	
	if !exists {
		bm.mutex.Lock()
		// Check again to avoid race condition
		bin, exists = bm.bins[binID]
		if !exists {
			bin = NewBin(binID)
			bm.bins[binID] = bin
		}
		bm.mutex.Unlock()
	}
	
	// Set timestamp and store the message
	msg.Timestamp = time.Now()
	bin.AddMessage(msg)
	
	// Broadcast to all subscribed clients
	bin.BroadcastMessage(msg)
}

// Subscribe adds a client to the subscribers list for a bin
func (bm *BinManager) Subscribe(binID uint64, clientID string, client Client) {
	bm.mutex.RLock()
	bin, exists := bm.bins[binID]
	bm.mutex.RUnlock()
	
	if !exists {
		bm.mutex.Lock()
		// Check again to avoid race condition
		bin, exists = bm.bins[binID]
		if !exists {
			bin = NewBin(binID)
			bm.bins[binID] = bin
		}
		bm.mutex.Unlock()
	}
	
	bin.AddClient(clientID, client)
}

// Unsubscribe removes a client from the subscribers list for a bin
func (bm *BinManager) Unsubscribe(binID uint64, clientID string) {
	bm.mutex.RLock()
	bin, exists := bm.bins[binID]
	bm.mutex.RUnlock()
	
	if exists {
		bin.RemoveClient(clientID)
	}
}

// GetRecentMessages retrieves messages from a bin within the retention period
func (bm *BinManager) GetRecentMessages(binID uint64) []*Message {
	bm.mutex.RLock()
	bin, exists := bm.bins[binID]
	bm.mutex.RUnlock()
	
	if !exists {
		return []*Message{}
	}
	
	return bin.GetRecentMessages(bm.retention)
}

// StartCleanupService starts a background service to clean up old messages
func (bm *BinManager) StartCleanupService(interval time.Duration) {
	if bm.cleanupTicker != nil {
		bm.cleanupTicker.Stop()
	}
	
	bm.cleanupTicker = time.NewTicker(interval)
	
	go func() {
		for {
			select {
			case <-bm.cleanupTicker.C:
				bm.cleanup()
			case <-bm.cleanupDone:
				return
			}
		}
	}()
}

// Stop stops the cleanup service
func (bm *BinManager) Stop() {
	if bm.cleanupTicker != nil {
		bm.cleanupTicker.Stop()
		close(bm.cleanupDone)
	}
}

// cleanup removes old messages from all bins
func (bm *BinManager) cleanup() {
	cutoff := time.Now().Add(-bm.retention)
	
	bm.mutex.RLock()
	bins := make([]*Bin, 0, len(bm.bins))
	for _, bin := range bm.bins {
		bins = append(bins, bin)
	}
	bm.mutex.RUnlock()
	
	for _, bin := range bins {
		bin.RemoveMessagesBefore(cutoff)
	}
}