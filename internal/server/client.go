package server

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yourusername/secure-messaging-poc/internal/binmanager"
)

// Client represents a connected WebSocket client
type Client struct {
	conn      *websocket.Conn
	certInfo  map[string]interface{}
	writeMu   sync.Mutex
	closeMu   sync.Mutex
	isClosed  bool
	createdAt time.Time
}

// NewClient creates a new client
func NewClient(conn *websocket.Conn, certInfo map[string]interface{}) *Client {
	return &Client{
		conn:      conn,
		certInfo:  certInfo,
		createdAt: time.Now(),
	}
}

// SendMessage sends a message to the client
func (c *Client) SendMessage(msg *binmanager.Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	
	if c.isClosed {
		return websocket.ErrCloseSent
	}
	
	return c.conn.WriteJSON(msg)
}

// GetCertificateInfo returns the client's certificate info
func (c *Client) GetCertificateInfo() map[string]interface{} {
	return c.certInfo
}

// GetCertificateID returns the client's certificate ID
func (c *Client) GetCertificateID() string {
	if serial, ok := c.certInfo["serial"].(string); ok {
		return serial
	}
	return ""
}

// Close closes the WebSocket connection
func (c *Client) Close() {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	
	if !c.isClosed {
		c.isClosed = true
		c.conn.Close()
	}
}

// IsActive checks if the client is still connected
func (c *Client) IsActive() bool {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	return !c.isClosed
}

// SendPing sends a ping message to check if client is still connected
func (c *Client) SendPing() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	
	if c.isClosed {
		return websocket.ErrCloseSent
	}
	
	return c.conn.WriteControl(
		websocket.PingMessage,
		[]byte{},
		time.Now().Add(time.Second),
	)
}