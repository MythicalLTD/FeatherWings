package modules

import (
	"context"
	"encoding/json"
	"sync"

	"emperror.dev/errors"
	"github.com/apex/log"
	"gorm.io/gorm"

	"github.com/mythicalltd/featherwings/internal/database"
	"github.com/mythicalltd/featherwings/internal/models"
)

// Manager handles registration and lifecycle of modules
type Manager struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// NewManager creates a new module manager
func NewManager() *Manager {
	return &Manager{
		modules: make(map[string]Module),
	}
}

// Register registers a module with the manager
func (m *Manager) Register(module Module) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := module.Name()
	if _, exists := m.modules[name]; exists {
		return errors.Errorf("module %s is already registered", name)
	}

	m.modules[name] = module
	log.WithField("module", name).Info("module registered")
	return nil
}

// Get retrieves a module by name
func (m *Manager) Get(name string) (Module, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	module, exists := m.modules[name]
	return module, exists
}

// List returns all registered modules
func (m *Manager) List() []Module {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Module, 0, len(m.modules))
	for _, module := range m.modules {
		result = append(result, module)
	}
	return result
}

// Enable enables a module by name
func (m *Manager) Enable(ctx context.Context, name string) error {
	m.mu.RLock()
	module, exists := m.modules[name]
	m.mu.RUnlock()

	if !exists {
		return errors.Errorf("module %s not found", name)
	}

	if module.Enabled() {
		return errors.Errorf("module %s is already enabled", name)
	}

	if err := module.Enable(ctx); err != nil {
		return errors.Wrapf(err, "failed to enable module %s", name)
	}

	// Persist enabled state
	if err := m.saveModuleState(name, true, module.GetConfig()); err != nil {
		log.WithError(err).WithField("module", name).Warn("failed to save module state")
	}

	log.WithField("module", name).Info("module enabled")
	return nil
}

// Disable disables a module by name
func (m *Manager) Disable(ctx context.Context, name string) error {
	m.mu.RLock()
	module, exists := m.modules[name]
	m.mu.RUnlock()

	if !exists {
		return errors.Errorf("module %s not found", name)
	}

	if !module.Enabled() {
		return errors.Errorf("module %s is already disabled", name)
	}

	if err := module.Disable(ctx); err != nil {
		return errors.Wrapf(err, "failed to disable module %s", name)
	}

	// Persist disabled state
	if err := m.saveModuleState(name, false, module.GetConfig()); err != nil {
		log.WithError(err).WithField("module", name).Warn("failed to save module state")
	}

	log.WithField("module", name).Info("module disabled")
	return nil
}

// saveModuleState saves module state and config to database
func (m *Manager) saveModuleState(name string, enabled bool, config interface{}) error {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return errors.Wrap(err, "failed to marshal module config")
	}

	var module models.Module
	result := database.Instance().Where("name = ?", name).First(&module)

	if result.Error == gorm.ErrRecordNotFound {
		// Create new record
		module = models.Module{
			Name:    name,
			Enabled: enabled,
			Config:  string(configJSON),
		}
		if err := database.Instance().Create(&module).Error; err != nil {
			return errors.Wrap(err, "failed to create module record")
		}
	} else if result.Error != nil {
		return errors.Wrap(result.Error, "failed to query module record")
	} else {
		// Update existing record
		module.Enabled = enabled
		module.Config = string(configJSON)
		if err := database.Instance().Save(&module).Error; err != nil {
			return errors.Wrap(err, "failed to update module record")
		}
	}

	return nil
}

// SaveModuleConfig saves module configuration to database
func (m *Manager) SaveModuleConfig(name string, config interface{}) error {
	m.mu.RLock()
	module, exists := m.modules[name]
	m.mu.RUnlock()

	if !exists {
		return errors.Errorf("module %s not found", name)
	}

	return m.saveModuleState(name, module.Enabled(), config)
}

// LoadModuleState loads module state and config from database
func (m *Manager) LoadModuleState(name string) (enabled bool, configJSON string, err error) {
	var module models.Module
	if err := database.Instance().Where("name = ?", name).First(&module).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, "", nil // Not found, return defaults
		}
		return false, "", errors.Wrap(err, "failed to load module state")
	}

	return module.Enabled, module.Config, nil
}

// RestoreModules restores all enabled modules from database
func (m *Manager) RestoreModules(ctx context.Context, serverManager interface{}) error {
	var modules []models.Module
	if err := database.Instance().Where("enabled = ?", true).Find(&modules).Error; err != nil {
		return errors.Wrap(err, "failed to load enabled modules from database")
	}

	// Add server manager to context if provided
	if serverManager != nil {
		ctx = context.WithValue(ctx, "server_manager", serverManager)
	}

	for _, moduleData := range modules {
		m.mu.RLock()
		module, exists := m.modules[moduleData.Name]
		m.mu.RUnlock()

		if !exists {
			log.WithField("module", moduleData.Name).Warn("module not found, skipping restore")
			continue
		}

		// Restore config if available
		if moduleData.Config != "" {
			var configData interface{}
			if err := json.Unmarshal([]byte(moduleData.Config), &configData); err != nil {
				log.WithError(err).WithField("module", moduleData.Name).Warn("failed to unmarshal module config, using defaults")
			} else {
				if err := module.SetConfig(configData); err != nil {
					log.WithError(err).WithField("module", moduleData.Name).Warn("failed to set module config, using defaults")
				}
			}
		}

		// Enable the module
		if err := module.Enable(ctx); err != nil {
			log.WithError(err).WithField("module", moduleData.Name).Error("failed to restore enabled module")
			// Mark as disabled in database if enable fails
			moduleData.Enabled = false
			database.Instance().Save(&moduleData)
			continue
		}

		log.WithField("module", moduleData.Name).Info("module restored and enabled")
	}

	return nil
}
