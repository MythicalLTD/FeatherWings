package models

import (
	"time"

	"gorm.io/gorm"
)

// FirewallRuleType represents the type of firewall rule
type FirewallRuleType string

const (
	FirewallRuleTypeAllow FirewallRuleType = "allow"
	FirewallRuleTypeBlock FirewallRuleType = "block"
)

// FirewallRule represents a firewall rule for a server
type FirewallRule struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Server UUID that this rule applies to
	ServerUUID string `gorm:"index;not null" json:"server_uuid"`

	// Remote IP address (CIDR notation supported, e.g., "192.168.1.1/32" or "192.168.1.0/24")
	RemoteIP string `gorm:"not null" json:"remote_ip"`

	// Server port this rule applies to
	ServerPort int `gorm:"not null" json:"server_port"`

	// Priority determines the order rules are applied (lower number = higher priority)
	Priority int `gorm:"default:100;not null" json:"priority"`

	// Type of rule: "allow" or "block"
	Type FirewallRuleType `gorm:"not null" json:"type"`

	// Protocol (tcp/udp/both) - defaults to tcp
	Protocol string `gorm:"default:tcp;not null" json:"protocol"`
}

// TableName specifies the table name for GORM
func (FirewallRule) TableName() string {
	return "firewall_rules"
}
