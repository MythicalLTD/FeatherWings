package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"gorm.io/gorm"

	"github.com/mythicalltd/featherwings/internal/database"
	"github.com/mythicalltd/featherwings/internal/models"
)

// Manager handles firewall rule management and iptables operations
type Manager struct {
	mu sync.RWMutex
}

// NewManager creates a new firewall manager instance
func NewManager() *Manager {
	return &Manager{}
}

// executeIptables executes an iptables command
func (m *Manager) executeIptables(command string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)

	// Capture stderr to include in error messages
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = nil

	err := cmd.Run()
	if err != nil {
		stderrStr := strings.TrimSpace(stderr.String())

		if ctx.Err() == context.DeadlineExceeded {
			if stderrStr != "" {
				return errors.Wrapf(err, "iptables command timed out after 10 seconds: %s", stderrStr)
			}
			return errors.Wrap(err, "iptables command timed out after 10 seconds")
		}
		if ctx.Err() == context.Canceled {
			if stderrStr != "" {
				return errors.Wrapf(err, "iptables command was cancelled: %s", stderrStr)
			}
			return errors.Wrap(err, "iptables command was cancelled")
		}

		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ProcessState != nil {
				if !exitError.ProcessState.Exited() {
					if stderrStr != "" {
						return errors.Wrapf(err, "iptables command was killed (likely permission issue or system limit): %s", stderrStr)
					}
					return errors.Wrap(err, "iptables command was killed (likely permission issue or system limit)")
				}
				// Include the actual command and stderr in the error
				if stderrStr != "" {
					log.WithFields(log.Fields{
						"command": command,
						"stderr":  stderrStr,
						"exit":    exitError.ExitCode(),
					}).Error("iptables command failed")
					return errors.Wrapf(err, "iptables command failed (exit code: %d): %s", exitError.ExitCode(), stderrStr)
				}
				log.WithFields(log.Fields{
					"command": command,
					"exit":    exitError.ExitCode(),
				}).Error("iptables command failed")
				return errors.Wrapf(err, "iptables command failed (exit code: %d)", exitError.ExitCode())
			}
		}

		if stderrStr != "" {
			log.WithFields(log.Fields{
				"command": command,
				"stderr":  stderrStr,
			}).Error("iptables command failed")
			return errors.Wrapf(err, "iptables command failed: %s", stderrStr)
		}
		log.WithField("command", command).Error("iptables command failed")
		return errors.Wrap(err, "iptables command failed")
	}
	return nil
}

// buildIptablesRule builds an iptables rule command
func (m *Manager) buildIptablesRule(rule *models.FirewallRule, action string) string {
	// Determine the chain and target based on rule type
	chain := "INPUT"
	var target string
	if rule.Type == models.FirewallRuleTypeAllow {
		target = "ACCEPT"
	} else {
		target = "DROP"
	}

	// Build the rule
	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	var ruleStr string

	// For INSERT, try priority-based positioning, otherwise append
	if action == "-I" {
		// Calculate position based on priority (lower priority number = higher in chain)
		// We'll insert after other rules with same or lower priority
		position := m.calculateRulePosition(rule)
		if position > 0 && position == 1 {
			// Insert at the beginning (position 1)
			ruleStr = fmt.Sprintf(
				"iptables -t filter %s %s -p %s -s %s --dport %d -j %s",
				action,
				chain,
				protocol,
				rule.RemoteIP,
				rule.ServerPort,
				target,
			)
		} else if position > 1 {
			// Insert at specific position
			ruleStr = fmt.Sprintf(
				"iptables -t filter %s %s %d -p %s -s %s --dport %d -j %s",
				action,
				chain,
				position,
				protocol,
				rule.RemoteIP,
				rule.ServerPort,
				target,
			)
		} else {
			// Position calculation failed or position is 0, use append instead
			ruleStr = fmt.Sprintf(
				"iptables -t filter -A %s -p %s -s %s --dport %d -j %s",
				chain,
				protocol,
				rule.RemoteIP,
				rule.ServerPort,
				target,
			)
		}
	} else {
		// For other actions (like -D), use standard format
		ruleStr = fmt.Sprintf(
			"iptables -t filter %s %s -p %s -s %s --dport %d -j %s",
			action,
			chain,
			protocol,
			rule.RemoteIP,
			rule.ServerPort,
			target,
		)
	}

	return ruleStr
}

// getChainLength gets the actual number of rules in the INPUT chain from iptables
func (m *Manager) getChainLength() (int, error) {
	// Use -L with --line-numbers and count the lines (excluding headers)
	cmd := exec.Command("sh", "-c", "iptables -t filter -L INPUT --line-numbers | tail -n +3 | wc -l")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return 0, errors.Wrap(err, "failed to get chain length")
	}

	output := strings.TrimSpace(stdout.String())
	length := 0
	fmt.Sscanf(output, "%d", &length)
	return length, nil
}

// calculateRulePosition calculates where to insert a rule based on its priority
// Returns 0 if we should append instead of insert at a specific position
func (m *Manager) calculateRulePosition(rule *models.FirewallRule) int {
	// Get actual chain length from iptables
	chainLength, err := m.getChainLength()
	if err != nil {
		log.WithError(err).Warn("failed to get chain length, will append rule")
		return 0 // Append instead of insert
	}

	// Get all rules for this server port and sort by priority
	var existingRules []models.FirewallRule
	database.Instance().Where("server_port = ? AND deleted_at IS NULL", rule.ServerPort).
		Order("priority ASC").
		Find(&existingRules)

	position := 1
	for _, r := range existingRules {
		if r.Priority <= rule.Priority {
			position++
		}
	}

	// Ensure position doesn't exceed chain length + 1 (for insertion at end)
	// If position calculation seems off, just append
	if position > chainLength+1 {
		log.WithFields(log.Fields{
			"calculated_position": position,
			"chain_length":        chainLength,
			"rule_id":             rule.ID,
		}).Debug("calculated position exceeds chain length, will append instead")
		return 0 // Append instead of insert
	}

	return position
}

// ApplyRule applies a firewall rule to iptables
func (m *Manager) ApplyRule(rule *models.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Set default protocol if not set
	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	target := map[models.FirewallRuleType]string{
		models.FirewallRuleTypeAllow: "ACCEPT",
		models.FirewallRuleTypeBlock: "DROP",
	}[rule.Type]

	// First, check if rule already exists in iptables (to avoid duplicates)
	checkCmd := fmt.Sprintf(
		"iptables -t filter -C INPUT -p %s -s %s --dport %d -j %s",
		protocol,
		rule.RemoteIP,
		rule.ServerPort,
		target,
	)

	// Try to check if rule exists (this will fail if it doesn't exist, which is fine)
	// We ignore the error here since we're just checking existence
	checkErr := m.executeIptables(checkCmd)
	if checkErr == nil {
		// Rule already exists, skip insertion
		log.WithFields(log.Fields{
			"rule_id":   rule.ID,
			"remote_ip": rule.RemoteIP,
			"port":      rule.ServerPort,
			"type":      rule.Type,
		}).Debug("firewall rule already exists in iptables, skipping")
		return nil
	}

	// Insert the rule with priority consideration
	insertCmd := m.buildIptablesRule(rule, "-I")
	log.WithFields(log.Fields{
		"rule_id": rule.ID,
		"command": insertCmd,
	}).Debug("applying firewall rule to iptables")

	if err := m.executeIptables(insertCmd); err != nil {
		return errors.Wrapf(err, "failed to apply firewall rule %d", rule.ID)
	}

	log.WithFields(log.Fields{
		"rule_id":   rule.ID,
		"server":    rule.ServerUUID,
		"remote_ip": rule.RemoteIP,
		"port":      rule.ServerPort,
		"type":      rule.Type,
		"priority":  rule.Priority,
	}).Info("firewall rule applied")

	return nil
}

// RemoveRule removes a firewall rule from iptables
func (m *Manager) RemoveRule(rule *models.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build delete command
	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	target := map[models.FirewallRuleType]string{
		models.FirewallRuleTypeAllow: "ACCEPT",
		models.FirewallRuleTypeBlock: "DROP",
	}[rule.Type]

	deleteCmd := fmt.Sprintf(
		"iptables -t filter -D INPUT -p %s -s %s --dport %d -j %s 2>/dev/null || true",
		protocol,
		rule.RemoteIP,
		rule.ServerPort,
		target,
	)

	if err := m.executeIptables(deleteCmd); err != nil {
		// Log warning but don't fail - rule might not exist
		log.WithError(err).WithField("rule_id", rule.ID).Warn("failed to remove firewall rule from iptables (rule may not exist)")
	} else {
		log.WithField("rule_id", rule.ID).Info("firewall rule removed")
	}

	return nil
}

// applyRuleUnlocked is like ApplyRule but without locking (for use within locked contexts)
func (m *Manager) applyRuleUnlocked(rule *models.FirewallRule) error {
	// Set default protocol if not set
	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	target := map[models.FirewallRuleType]string{
		models.FirewallRuleTypeAllow: "ACCEPT",
		models.FirewallRuleTypeBlock: "DROP",
	}[rule.Type]

	// First, check if rule already exists in iptables (to avoid duplicates)
	checkCmd := fmt.Sprintf(
		"iptables -t filter -C INPUT -p %s -s %s --dport %d -j %s",
		protocol,
		rule.RemoteIP,
		rule.ServerPort,
		target,
	)

	// Try to check if rule exists (this will fail if it doesn't exist, which is fine)
	checkErr := m.executeIptables(checkCmd)
	if checkErr == nil {
		// Rule already exists, skip insertion
		log.WithFields(log.Fields{
			"rule_id":   rule.ID,
			"remote_ip": rule.RemoteIP,
			"port":      rule.ServerPort,
			"type":      rule.Type,
		}).Debug("firewall rule already exists in iptables, skipping")
		return nil
	}

	// Insert the rule with priority consideration
	insertCmd := m.buildIptablesRule(rule, "-I")
	log.WithFields(log.Fields{
		"rule_id": rule.ID,
		"command": insertCmd,
	}).Debug("applying firewall rule to iptables")

	if err := m.executeIptables(insertCmd); err != nil {
		return errors.Wrapf(err, "failed to apply firewall rule %d", rule.ID)
	}

	log.WithFields(log.Fields{
		"rule_id":   rule.ID,
		"server":    rule.ServerUUID,
		"remote_ip": rule.RemoteIP,
		"port":      rule.ServerPort,
		"type":      rule.Type,
		"priority":  rule.Priority,
	}).Debug("firewall rule applied")

	return nil
}

// SyncRules syncs all firewall rules from database to iptables
func (m *Manager) SyncRules(serverUUID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get all active rules for this server
	var rules []models.FirewallRule
	if err := database.Instance().Where("server_uuid = ? AND deleted_at IS NULL", serverUUID).
		Order("priority ASC, created_at ASC").
		Find(&rules).Error; err != nil {
		return errors.Wrap(err, "failed to fetch firewall rules")
	}

	if len(rules) == 0 {
		log.WithField("server", serverUUID).Debug("no firewall rules to sync")
		return nil
	}

	// Apply rules in priority order (using unlocked version since we already have the lock)
	appliedCount := 0
	failedCount := 0
	for _, rule := range rules {
		if err := m.applyRuleUnlocked(&rule); err != nil {
			log.WithError(err).WithField("rule_id", rule.ID).Warn("failed to apply firewall rule during sync")
			failedCount++
			// Continue with other rules
		} else {
			appliedCount++
		}
	}

	log.WithFields(log.Fields{
		"server":  serverUUID,
		"total":   len(rules),
		"applied": appliedCount,
		"failed":  failedCount,
	}).Info("synced firewall rules")

	return nil
}

// GetRules returns all firewall rules for a server
func (m *Manager) GetRules(serverUUID string) ([]models.FirewallRule, error) {
	var rules []models.FirewallRule
	if err := database.Instance().Where("server_uuid = ? AND deleted_at IS NULL", serverUUID).
		Order("priority ASC, created_at ASC").
		Find(&rules).Error; err != nil {
		return nil, errors.Wrap(err, "failed to fetch firewall rules")
	}
	return rules, nil
}

// CreateRule creates a new firewall rule
func (m *Manager) CreateRule(rule *models.FirewallRule) error {
	// Validate rule type
	if rule.Type != models.FirewallRuleTypeAllow && rule.Type != models.FirewallRuleTypeBlock {
		return errors.Errorf("invalid rule type: %s (must be 'allow' or 'block')", rule.Type)
	}

	// Validate protocol
	if rule.Protocol == "" {
		rule.Protocol = "tcp"
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return errors.Errorf("invalid protocol: %s (must be 'tcp' or 'udp')", rule.Protocol)
	}

	// Validate port range
	if rule.ServerPort < 1 || rule.ServerPort > 65535 {
		return errors.Errorf("invalid port: %d (must be between 1 and 65535)", rule.ServerPort)
	}

	// Set default priority if not set
	if rule.Priority == 0 {
		rule.Priority = 100
	}

	// Save to database
	if err := database.Instance().Create(rule).Error; err != nil {
		return errors.Wrap(err, "failed to create firewall rule")
	}

	// Apply to iptables
	if err := m.ApplyRule(rule); err != nil {
		// If iptables apply fails, delete from database
		database.Instance().Delete(rule)
		return errors.Wrap(err, "failed to apply firewall rule to iptables")
	}

	return nil
}

// UpdateRule updates an existing firewall rule
func (m *Manager) UpdateRule(ruleID uint, updates *models.FirewallRule) error {
	// Get existing rule
	var existingRule models.FirewallRule
	if err := database.Instance().First(&existingRule, ruleID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.Errorf("firewall rule %d not found", ruleID)
		}
		return errors.Wrap(err, "failed to fetch firewall rule")
	}

	// Remove old rule from iptables
	if err := m.RemoveRule(&existingRule); err != nil {
		log.WithError(err).Warn("failed to remove old firewall rule during update")
	}

	// Update fields
	if updates.RemoteIP != "" {
		existingRule.RemoteIP = updates.RemoteIP
	}
	if updates.ServerPort != 0 {
		existingRule.ServerPort = updates.ServerPort
	}
	if updates.Priority != 0 {
		existingRule.Priority = updates.Priority
	}
	if updates.Type != "" {
		existingRule.Type = updates.Type
	}
	if updates.Protocol != "" {
		existingRule.Protocol = updates.Protocol
	}

	// Validate updated rule
	if existingRule.Type != models.FirewallRuleTypeAllow && existingRule.Type != models.FirewallRuleTypeBlock {
		return errors.Errorf("invalid rule type: %s", existingRule.Type)
	}

	// Save to database
	if err := database.Instance().Save(&existingRule).Error; err != nil {
		return errors.Wrap(err, "failed to update firewall rule")
	}

	// Apply new rule to iptables
	if err := m.ApplyRule(&existingRule); err != nil {
		return errors.Wrap(err, "failed to apply updated firewall rule to iptables")
	}

	return nil
}

// DeleteRule deletes a firewall rule
func (m *Manager) DeleteRule(ruleID uint) error {
	// Get existing rule
	var rule models.FirewallRule
	if err := database.Instance().First(&rule, ruleID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.Errorf("firewall rule %d not found", ruleID)
		}
		return errors.Wrap(err, "failed to fetch firewall rule")
	}

	// Remove from iptables
	if err := m.RemoveRule(&rule); err != nil {
		log.WithError(err).Warn("failed to remove firewall rule from iptables during delete")
	}

	// Delete from database (soft delete)
	if err := database.Instance().Delete(&rule).Error; err != nil {
		return errors.Wrap(err, "failed to delete firewall rule")
	}

	return nil
}

// GetRuleByID returns a single firewall rule by ID
func (m *Manager) GetRuleByID(ruleID uint) (*models.FirewallRule, error) {
	var rule models.FirewallRule
	if err := database.Instance().First(&rule, ruleID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.Errorf("firewall rule %d not found", ruleID)
		}
		return nil, errors.Wrap(err, "failed to fetch firewall rule")
	}
	return &rule, nil
}

// GetRulesByPort returns all firewall rules for a specific port
func (m *Manager) GetRulesByPort(serverUUID string, port int) ([]models.FirewallRule, error) {
	var rules []models.FirewallRule
	if err := database.Instance().Where("server_uuid = ? AND server_port = ? AND deleted_at IS NULL", serverUUID, port).
		Order("priority ASC, created_at ASC").
		Find(&rules).Error; err != nil {
		return nil, errors.Wrap(err, "failed to fetch firewall rules")
	}
	return rules, nil
}

// CleanupInvalidPortRules removes firewall rules for ports that are no longer allocated to a server
func (m *Manager) CleanupInvalidPortRules(serverUUID string, validPorts map[int]bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get all rules for this server
	var rules []models.FirewallRule
	if err := database.Instance().Where("server_uuid = ? AND deleted_at IS NULL", serverUUID).Find(&rules).Error; err != nil {
		return errors.Wrap(err, "failed to fetch firewall rules for cleanup")
	}

	removedCount := 0
	for _, rule := range rules {
		// Check if the port is still valid
		if !validPorts[rule.ServerPort] {
			// Remove from iptables
			if err := m.RemoveRule(&rule); err != nil {
				log.WithError(err).WithField("rule_id", rule.ID).Warn("failed to remove invalid firewall rule from iptables")
			}
			// Soft delete from database
			if err := database.Instance().Delete(&rule).Error; err != nil {
				log.WithError(err).WithField("rule_id", rule.ID).Warn("failed to delete invalid firewall rule from database")
			} else {
				removedCount++
			}
		}
	}

	if removedCount > 0 {
		log.WithFields(log.Fields{
			"server": serverUUID,
			"count":  removedCount,
		}).Info("cleaned up invalid firewall rules for server")
	}

	return nil
}

// DeleteAllRulesForServer deletes all firewall rules for a server
func (m *Manager) DeleteAllRulesForServer(serverUUID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get all rules for this server
	var rules []models.FirewallRule
	if err := database.Instance().Where("server_uuid = ? AND deleted_at IS NULL", serverUUID).Find(&rules).Error; err != nil {
		return errors.Wrap(err, "failed to fetch firewall rules for deletion")
	}

	// Remove each rule from iptables
	for _, rule := range rules {
		if err := m.RemoveRule(&rule); err != nil {
			log.WithError(err).WithField("rule_id", rule.ID).Warn("failed to remove firewall rule from iptables during server deletion")
		}
	}

	// Soft delete all rules from database
	if err := database.Instance().Where("server_uuid = ? AND deleted_at IS NULL", serverUUID).
		Delete(&models.FirewallRule{}).Error; err != nil {
		return errors.Wrap(err, "failed to delete firewall rules from database")
	}

	log.WithFields(log.Fields{
		"server": serverUUID,
		"count":  len(rules),
	}).Info("deleted all firewall rules for server")

	return nil
}

// RebuildAllRules rebuilds all firewall rules in iptables (useful for system restart)
func (m *Manager) RebuildAllRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get all active rules grouped by server
	var allRules []models.FirewallRule
	if err := database.Instance().Where("deleted_at IS NULL").
		Order("server_uuid ASC, priority ASC, created_at ASC").
		Find(&allRules).Error; err != nil {
		return errors.Wrap(err, "failed to fetch all firewall rules")
	}

	if len(allRules) == 0 {
		log.Debug("no firewall rules to rebuild")
		return nil
	}

	// Group by server
	serverRules := make(map[string][]models.FirewallRule)
	for _, rule := range allRules {
		serverRules[rule.ServerUUID] = append(serverRules[rule.ServerUUID], rule)
	}

	// Apply rules for each server (using unlocked version since we already have the lock)
	totalApplied := 0
	totalFailed := 0
	for serverUUID, rules := range serverRules {
		appliedCount := 0
		failedCount := 0
		for _, rule := range rules {
			if err := m.applyRuleUnlocked(&rule); err != nil {
				log.WithError(err).WithFields(log.Fields{
					"rule_id": rule.ID,
					"server":  serverUUID,
				}).Warn("failed to apply firewall rule during rebuild")
				failedCount++
			} else {
				appliedCount++
			}
		}
		totalApplied += appliedCount
		totalFailed += failedCount
		log.WithFields(log.Fields{
			"server":  serverUUID,
			"total":   len(rules),
			"applied": appliedCount,
			"failed":  failedCount,
		}).Info("rebuilt firewall rules")
	}

	log.WithFields(log.Fields{
		"total":   len(allRules),
		"applied": totalApplied,
		"failed":  totalFailed,
	}).Info("finished rebuilding all firewall rules")

	return nil
}

// ValidateIP validates an IP address or CIDR notation
func ValidateIP(ip string) error {
	if ip == "" {
		return errors.New("IP address cannot be empty")
	}

	// Try parsing as CIDR first
	_, _, err := net.ParseCIDR(ip)
	if err == nil {
		return nil
	}

	// Try parsing as regular IP
	if net.ParseIP(ip) != nil {
		return nil
	}

	return errors.Errorf("invalid IP address or CIDR: %s", ip)
}
