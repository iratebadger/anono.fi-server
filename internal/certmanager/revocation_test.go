package certmanager

import (
	"testing"
	"time"
)

func TestRevocationManagerBasic(t *testing.T) {
	rm := NewRevocationManager()
	
	// Register certificate hierarchy
	//   root
	//   ├── child1
	//   │   ├── grandchild1
	//   │   └── grandchild2
	//   └── child2
	
	rm.RegisterCertificate("child1", "root")
	rm.RegisterCertificate("child2", "root")
	rm.RegisterCertificate("grandchild1", "child1")
	rm.RegisterCertificate("grandchild2", "child1")
	
	// Initially no certificates should be revoked
	if rm.IsRevoked("root") {
		t.Error("Root certificate should not be revoked initially")
	}
	
	if rm.IsRevoked("child1") {
		t.Error("Child1 certificate should not be revoked initially")
	}
	
	// Revoke a certificate
	rm.Revoke("child1")
	
	// Check revocation status
	if !rm.IsRevoked("child1") {
		t.Error("Child1 certificate should be revoked after calling Revoke")
	}
	
	if rm.IsRevoked("root") {
		t.Error("Revoking a child should not revoke its parent")
	}
	
	if rm.IsRevoked("child2") {
		t.Error("Revoking a certificate should not revoke its siblings")
	}
	
	if rm.IsRevoked("grandchild1") {
		t.Error("Revoking a certificate should not automatically revoke its children")
	}
	
	// Check child count
	if count := rm.GetChildCount("root"); count != 2 {
		t.Errorf("Root should have 2 children, got %d", count)
	}
	
	if count := rm.GetChildCount("child1"); count != 2 {
		t.Errorf("Child1 should have 2 children, got %d", count)
	}
	
	if count := rm.GetChildCount("nonexistent"); count != 0 {
		t.Errorf("Nonexistent certificate should have 0 children, got %d", count)
	}
}

func TestRevocationWithChildren(t *testing.T) {
	rm := NewRevocationManager()
	
	// Register certificate hierarchy
	rm.RegisterCertificate("child1", "root")
	rm.RegisterCertificate("child2", "root")
	rm.RegisterCertificate("grandchild1", "child1")
	rm.RegisterCertificate("grandchild2", "child1")
	rm.RegisterCertificate("greatgrandchild", "grandchild1")
	
	// Revoke with children
	rm.RevokeWithChildren("child1")
	
	// Parent should not be revoked
	if rm.IsRevoked("root") {
		t.Error("Revoking a child with its children should not revoke its parent")
	}
	
	// Sibling should not be revoked
	if rm.IsRevoked("child2") {
		t.Error("Revoking a certificate with its children should not revoke its siblings")
	}
	
	// The certificate and all its descendants should be revoked
	if !rm.IsRevoked("child1") {
		t.Error("child1 should be revoked")
	}
	
	if !rm.IsRevoked("grandchild1") {
		t.Error("grandchild1 should be revoked when parent is revoked with children")
	}
	
	if !rm.IsRevoked("grandchild2") {
		t.Error("grandchild2 should be revoked when parent is revoked with children")
	}
	
	if !rm.IsRevoked("greatgrandchild") {
		t.Error("greatgrandchild should be revoked when ancestor is revoked with children")
	}
}

func TestGetRevokedCertificates(t *testing.T) {
	rm := NewRevocationManager()
	
	// Initially no certificates should be revoked
	revoked := rm.GetRevokedCertificates()
	if len(revoked) != 0 {
		t.Errorf("Initially should have 0 revoked certificates, got %d", len(revoked))
	}
	
	// Revoke some certificates
	now := time.Now()
	rm.Revoke("cert1")
	time.Sleep(10 * time.Millisecond)
	rm.Revoke("cert2")
	
	// Check revoked certificates
	revoked = rm.GetRevokedCertificates()
	if len(revoked) != 2 {
		t.Errorf("Should have 2 revoked certificates, got %d", len(revoked))
	}
	
	if _, exists := revoked["cert1"]; !exists {
		t.Error("cert1 should be in the revoked certificates list")
	}
	
	if _, exists := revoked["cert2"]; !exists {
		t.Error("cert2 should be in the revoked certificates list")
	}
	
	// Check revocation times
	if revoked["cert1"].Before(now) {
		t.Error("cert1 revocation time should be after the test started")
	}
	
	if revoked["cert2"].Before(revoked["cert1"]) {
		t.Error("cert2 should be revoked after cert1")
	}
}

func TestConcurrentRevocation(t *testing.T) {
	rm := NewRevocationManager()
	
	// Register a certificate hierarchy
	for i := 0; i < 10; i++ {
		parentID := "root"
		childID := "child" + string(rune('0'+i))
		rm.RegisterCertificate(childID, parentID)
		
		for j := 0; j < 10; j++ {
			grandchildID := childID + "_grandchild" + string(rune('0'+j))
			rm.RegisterCertificate(grandchildID, childID)
		}
	}
	
	// Concurrently revoke certificates
	done := make(chan bool)
	go func() {
		rm.Revoke("child0")
		done <- true
	}()
	
	go func() {
		rm.Revoke("child1")
		done <- true
	}()
	
	go func() {
		rm.RevokeWithChildren("child2")
		done <- true
	}()
	
	go func() {
		rm.GetRevokedCertificates()
		done <- true
	}()
	
	// Wait for all goroutines to complete
	for i := 0; i < 4; i++ {
		<-done
	}
	
	// Check revocation status
	if !rm.IsRevoked("child0") {
		t.Error("child0 should be revoked")
	}
	
	if !rm.IsRevoked("child1") {
		t.Error("child1 should be revoked")
	}
	
	if !rm.IsRevoked("child2") {
		t.Error("child2 should be revoked")
	}
	
	if !rm.IsRevoked("child2_grandchild0") {
		t.Error("child2_grandchild0 should be revoked")
	}
	
	if rm.IsRevoked("child3") {
		t.Error("child3 should not be revoked")
	}
}