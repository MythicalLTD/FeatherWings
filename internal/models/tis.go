package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// TISMetadata represents JSON metadata stored in TIS tables
type TISMetadata map[string]interface{}

// Value implements the driver.Valuer interface for TISMetadata
func (m TISMetadata) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Scan implements the sql.Scanner interface for TISMetadata
func (m *TISMetadata) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		*m = TISMetadata{}
		return nil
	}
	return json.Unmarshal(bytes, m)
}

// DetectionTypes represents a JSON array of detection types
type DetectionTypes []string

// Value implements the driver.Valuer interface for DetectionTypes
func (d DetectionTypes) Value() (driver.Value, error) {
	if d == nil {
		return "[]", nil
	}
	return json.Marshal(d)
}

// Scan implements the sql.Scanner interface for DetectionTypes
func (d *DetectionTypes) Scan(value interface{}) error {
	if value == nil {
		*d = DetectionTypes{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		*d = DetectionTypes{}
		return nil
	}
	return json.Unmarshal(bytes, d)
}

// MaliciousHash represents a confirmed malicious file hash
type MaliciousHash struct {
	Hash          string      `gorm:"primaryKey;not null;index" json:"hash"`
	FileName      string      `gorm:"not null" json:"file_name"`
	DetectionType string      `gorm:"not null" json:"detection_type"`
	FirstSeen     time.Time   `gorm:"not null;default:CURRENT_TIMESTAMP" json:"first_seen"`
	LastSeen      time.Time   `gorm:"not null;default:CURRENT_TIMESTAMP" json:"last_seen"`
	TimesDetected int         `gorm:"not null;default:1" json:"times_detected"`
	SourceServer  string      `gorm:"not null" json:"source_server"`
	Metadata      TISMetadata `gorm:"type:text" json:"metadata"`
}

// TableName specifies the table name for MaliciousHash
func (MaliciousHash) TableName() string {
	return "malicious_hashes"
}

// BeforeCreate sets default values before creating a record
func (m *MaliciousHash) BeforeCreate(_ *gorm.DB) error {
	now := time.Now().UTC()
	if m.FirstSeen.IsZero() {
		m.FirstSeen = now
	}
	if m.LastSeen.IsZero() {
		m.LastSeen = now
	}
	if m.Metadata == nil {
		m.Metadata = TISMetadata{}
	}
	if m.TimesDetected == 0 {
		m.TimesDetected = 1
	}
	return nil
}

// BeforeUpdate updates LastSeen timestamp
func (m *MaliciousHash) BeforeUpdate(_ *gorm.DB) error {
	m.LastSeen = time.Now().UTC()
	return nil
}

// UnconfirmedHash represents a hash pending confirmation
type UnconfirmedHash struct {
	Hash          string      `gorm:"primaryKey;not null;index" json:"hash"`
	FileName      string      `gorm:"not null" json:"file_name"`
	DetectionType string      `gorm:"not null" json:"detection_type"`
	FirstSeen     time.Time   `gorm:"not null;default:CURRENT_TIMESTAMP" json:"first_seen"`
	LastSeen      time.Time   `gorm:"not null;default:CURRENT_TIMESTAMP" json:"last_seen"`
	TimesDetected int         `gorm:"not null;default:1" json:"times_detected"`
	SourceServer  string      `gorm:"not null" json:"source_server"`
	Metadata      TISMetadata `gorm:"type:text" json:"metadata"`
}

// TableName specifies the table name for UnconfirmedHash
func (UnconfirmedHash) TableName() string {
	return "unconfirmed_hashes"
}

// BeforeCreate sets default values before creating a record
func (u *UnconfirmedHash) BeforeCreate(_ *gorm.DB) error {
	now := time.Now().UTC()
	if u.FirstSeen.IsZero() {
		u.FirstSeen = now
	}
	if u.LastSeen.IsZero() {
		u.LastSeen = now
	}
	if u.Metadata == nil {
		u.Metadata = TISMetadata{}
	}
	if u.TimesDetected == 0 {
		u.TimesDetected = 1
	}
	return nil
}

// BeforeUpdate updates LastSeen timestamp
func (u *UnconfirmedHash) BeforeUpdate(_ *gorm.DB) error {
	u.LastSeen = time.Now().UTC()
	return nil
}

// FlaggedServer represents a server that has been flagged for submitting malicious hashes
type FlaggedServer struct {
	ServerID       string         `gorm:"primaryKey;not null;index" json:"server_id"`
	FirstFlagged   time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP" json:"first_flagged"`
	LastFlagged    time.Time      `gorm:"not null;default:CURRENT_TIMESTAMP" json:"last_flagged"`
	TimesFlagged   int            `gorm:"not null;default:1" json:"times_flagged"`
	DetectionTypes DetectionTypes `gorm:"type:text" json:"detection_types"`
	LastHash       string         `gorm:"" json:"last_hash"`
	Metadata       TISMetadata    `gorm:"type:text" json:"metadata"`
}

// TableName specifies the table name for FlaggedServer
func (FlaggedServer) TableName() string {
	return "flagged_servers"
}

// BeforeCreate sets default values before creating a record
func (f *FlaggedServer) BeforeCreate(_ *gorm.DB) error {
	now := time.Now().UTC()
	if f.FirstFlagged.IsZero() {
		f.FirstFlagged = now
	}
	if f.LastFlagged.IsZero() {
		f.LastFlagged = now
	}
	if f.DetectionTypes == nil {
		f.DetectionTypes = DetectionTypes{}
	}
	if f.Metadata == nil {
		f.Metadata = TISMetadata{}
	}
	if f.TimesFlagged == 0 {
		f.TimesFlagged = 1
	}
	return nil
}

// BeforeUpdate updates LastFlagged timestamp
func (f *FlaggedServer) BeforeUpdate(_ *gorm.DB) error {
	f.LastFlagged = time.Now().UTC()
	return nil
}
