package models

import (
	"time"

	"gorm.io/gorm"
)

// Module represents a module's persisted state and configuration
type Module struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name    string `gorm:"uniqueIndex;not null" json:"name"`
	Enabled bool   `gorm:"default:false" json:"enabled"`
	Config  string `gorm:"type:text" json:"config"` // JSON encoded config
}
