package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
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

// executeIptables executes an iptables command with explicit arguments to prevent command injection
func (m *Manager) executeIptables(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "iptables", args...)

	// Capture stderr to include in error messages
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = nil

	err := cmd.Run()
	if err != nil {
		stderrStr := strings.TrimSpace(stderr.String())
		cmdStr := strings.Join(append([]string{"iptables"}, args...), " ")

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
						"command": cmdStr,
						"stderr":  stderrStr,
						"exit":    exitError.ExitCode(),
					}).Error("iptables command failed")
					return errors.Wrapf(err, "iptables command failed (exit code: %d): %s", exitError.ExitCode(), stderrStr)
				}
				log.WithFields(log.Fields{
					"command": cmdStr,
					"exit":    exitError.ExitCode(),
				}).Error("iptables command failed")
				return errors.Wrapf(err, "iptables command failed (exit code: %d)", exitError.ExitCode())
			}
		}

		if stderrStr != "" {
			log.WithFields(log.Fields{
				"command": cmdStr,
				"stderr":  stderrStr,
			}).Error("iptables command failed")
			return errors.Wrapf(err, "iptables command failed: %s", stderrStr)
		}
		log.WithField("command", cmdStr).Error("iptables command failed")
		return errors.Wrap(err, "iptables command failed")
	}
	return nil
}

// validateProtocol validates that protocol is tcp or udp
func validateProtocol(protocol string) error {
	if protocol != "tcp" && protocol != "udp" {
		return errors.Errorf("invalid protocol: %s (must be 'tcp' or 'udp')", protocol)
	}
	return nil
}

// buildIptablesRuleArgs builds iptables command arguments to prevent command injection
// Validates all inputs before building the command
func (m *Manager) buildIptablesRuleArgs(rule *models.FirewallRule, action string) ([]string, error) {
	// Validate IP address before use
	if err := ValidateIP(rule.RemoteIP); err != nil {
		return nil, errors.Wrap(err, "invalid remote IP")
	}

	// Validate and normalize protocol
	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	if err := validateProtocol(protocol); err != nil {
		return nil, err
	}

	// Validate port
	if rule.ServerPort < 1 || rule.ServerPort > 65535 {
		return nil, errors.Errorf("invalid port: %d (must be between 1 and 65535)", rule.ServerPort)
	}

	// For Docker containers, traffic is DNAT'd in PREROUTING (nat table)
	// This means the destination port changes in FORWARD chain
	// We need to match on the original destination port BEFORE DNAT
	// Solution: Use PREROUTING in the raw table to match original port before DNAT
	table := "raw"
	chain := "PREROUTING"

	var target string
	if rule.Type == models.FirewallRuleTypeAllow {
		// For allow rules, we use ACCEPT to let the packet continue
		target = "ACCEPT"
	} else {
		// For blocking, use DROP to stop the packet before DNAT
		target = "DROP"
	}

	// Build arguments array
	args := []string{"-t", table}

	// For INSERT, try priority-based positioning, otherwise append
	if action == "-I" {
		// Calculate position based on priority
		position := m.calculateRulePosition(rule)
		if position > 0 && position == 1 {
			// Insert at the beginning (position 1)
			args = append(args, "-I", chain)
		} else if position > 1 {
			// Insert at specific position
			args = append(args, "-I", chain, fmt.Sprintf("%d", position))
		} else {
			// Position calculation failed, use append instead
			args = append(args, "-A", chain)
		}
	} else {
		// For other actions (like -D), use standard format
		args = append(args, action, chain)
	}

	// Add rule parameters
	args = append(args,
		"-p", protocol,
		"-s", rule.RemoteIP,
		"--dport", fmt.Sprintf("%d", rule.ServerPort),
		"-j", target,
	)

	return args, nil
}

// getChainLength gets the actual number of rules in the raw/PREROUTING chain from iptables
// We use raw/PREROUTING for both allow and block rules to match original destination port before DNAT
func (m *Manager) getChainLength(ruleType models.FirewallRuleType) (int, error) {
	table := "raw"
	chain := "PREROUTING"

	// Use -L with --line-numbers and count the lines (excluding headers)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("iptables -t %s -L %s --line-numbers 2>/dev/null | tail -n +3 | wc -l", table, chain))
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil

	err := cmd.Run()
	if err != nil {
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
	// Get actual chain length from iptables (for the appropriate table/chain based on rule type)
	chainLength, err := m.getChainLength(rule.Type)
	if err != nil {
		log.WithError(err).Debug("failed to get chain length, will append rule")
		return 0 // Append instead of insert
	}

	// If chain is empty, insert at position 1 (beginning)
	if chainLength == 0 {
		return 1
	}

	// Get all rules from database that are already applied (same server, same port, same protocol)
	// We only count rules that should be in iptables
	var existingRules []models.FirewallRule
	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	database.Instance().Where("server_uuid = ? AND server_port = ? AND protocol = ? AND deleted_at IS NULL",
		rule.ServerUUID, rule.ServerPort, protocol).
		Order("priority ASC, created_at ASC").
		Find(&existingRules)

	// Count how many existing rules have priority <= our rule's priority
	// These should be inserted before our rule
	position := 1
	for _, r := range existingRules {
		// Skip the current rule if we're updating it
		if r.ID == rule.ID {
			continue
		}
		if r.Priority < rule.Priority || (r.Priority == rule.Priority && r.CreatedAt.Before(rule.CreatedAt)) {
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
			"protocol":            protocol,
		}).Debug("calculated position exceeds chain length, will append instead")
		return 0 // Append instead of insert
	}

	// If position is valid, return it
	if position >= 1 && position <= chainLength+1 {
		return position
	}

	// Fallback to append
	return 0
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

	// Validate inputs before building commands
	if err := ValidateIP(rule.RemoteIP); err != nil {
		return errors.Wrap(err, "invalid remote IP")
	}
	if err := validateProtocol(protocol); err != nil {
		return errors.Wrap(err, "invalid protocol")
	}

	// First, check if rule already exists in iptables (to avoid duplicates)
	// Use -C (check) which returns 0 if rule exists, 1 if it doesn't
	checkArgs := []string{
		"-t", "raw",
		"-C", "PREROUTING",
		"-p", protocol,
		"-s", rule.RemoteIP,
		"--dport", fmt.Sprintf("%d", rule.ServerPort),
		"-j", target,
	}

	// Execute check silently - we expect it to fail (exit code 1) if rule doesn't exist
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "iptables", checkArgs...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	checkErr := cmd.Run()
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
	// If check failed (exit code 1), rule doesn't exist - this is expected, continue with insertion

	// Build and insert the rule with priority consideration
	insertArgs, err := m.buildIptablesRuleArgs(rule, "-I")
	if err != nil {
		return errors.Wrap(err, "failed to build iptables rule arguments")
	}

	log.WithFields(log.Fields{
		"rule_id": rule.ID,
		"command": strings.Join(append([]string{"iptables"}, insertArgs...), " "),
	}).Debug("applying firewall rule to iptables")

	if err := m.executeIptables(insertArgs...); err != nil {
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
	return m.removeRuleUnlocked(rule)
}

// removeRuleUnlocked removes a firewall rule from iptables without acquiring the lock
// This is used internally when the lock is already held
func (m *Manager) removeRuleUnlocked(rule *models.FirewallRule) error {
	// Validate inputs
	if err := ValidateIP(rule.RemoteIP); err != nil {
		return errors.Wrap(err, "invalid remote IP")
	}

	protocol := rule.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	if err := validateProtocol(protocol); err != nil {
		return errors.Wrap(err, "invalid protocol")
	}

	target := map[models.FirewallRuleType]string{
		models.FirewallRuleTypeAllow: "ACCEPT",
		models.FirewallRuleTypeBlock: "DROP",
	}[rule.Type]

	// We use raw table PREROUTING for both allow and block rules
	// Build delete command arguments
	deleteArgs := []string{
		"-t", "raw",
		"-D", "PREROUTING",
		"-p", protocol,
		"-s", rule.RemoteIP,
		"--dport", strconv.Itoa(rule.ServerPort),
		"-j", target,
	}

	if err := m.executeIptables(deleteArgs...); err != nil {
		// Log warning but don't fail - rule might not exist in iptables
		// This can happen if iptables was manually modified or rules were cleared
		log.WithError(err).WithFields(log.Fields{
			"rule_id":   rule.ID,
			"remote_ip": rule.RemoteIP,
			"port":      rule.ServerPort,
			"type":      rule.Type,
		}).Warn("failed to remove firewall rule from iptables (rule may not exist in iptables)")
		// Still return nil - the rule might not exist, which is fine
		return nil
	}

	// Rule successfully removed from iptables
	log.WithFields(log.Fields{
		"rule_id":   rule.ID,
		"remote_ip": rule.RemoteIP,
		"port":      rule.ServerPort,
		"type":      rule.Type,
	}).Debug("firewall rule removed from iptables")

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
	// Use -C (check) which returns 0 if rule exists, 1 if it doesn't
	// Redirect stderr to /dev/null to suppress the expected "Bad rule" message when rule doesn't exist
	// In DOCKER-USER, --dport matches the original host port
	checkCmd := fmt.Sprintf(
		"iptables -t filter -C DOCKER-USER -p %s -s %s --dport %d -j %s 2>/dev/null",
		protocol,
		rule.RemoteIP,
		rule.ServerPort,
		target,
	)

	// Execute check silently - we expect it to fail (exit code 1) if rule doesn't exist
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", checkCmd)
	cmd.Stdout = nil
	cmd.Stderr = nil

	checkErr := cmd.Run()
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
	// If check failed (exit code 1), rule doesn't exist - this is expected, continue with insertion

	// Build and insert the rule with priority consideration
	insertArgs, err := m.buildIptablesRuleArgs(rule, "-I")
	if err != nil {
		return errors.Wrap(err, "failed to build iptables rule arguments")
	}

	log.WithFields(log.Fields{
		"rule_id": rule.ID,
		"command": strings.Join(append([]string{"iptables"}, insertArgs...), " "),
	}).Debug("applying firewall rule to iptables")

	if err := m.executeIptables(insertArgs...); err != nil {
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
		// If iptables apply fails, hard delete from database (rollback)
		if delErr := database.Instance().Unscoped().Delete(rule).Error; delErr != nil {
			log.WithError(delErr).WithField("rule_id", rule.ID).Error("failed to rollback firewall rule creation")
		}
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
// For block rules, this will unblock the IP by removing the DROP rule from iptables
// For allow rules, this will remove the explicit ALLOW rule (default behavior will apply)
func (m *Manager) DeleteRule(ruleID uint) error {
	// Get existing rule
	var rule models.FirewallRule
	if err := database.Instance().First(&rule, ruleID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.Errorf("firewall rule %d not found", ruleID)
		}
		return errors.Wrap(err, "failed to fetch firewall rule")
	}

	// Remove from iptables first (this will unblock if it's a block rule)
	if err := m.RemoveRule(&rule); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"rule_id":   rule.ID,
			"remote_ip": rule.RemoteIP,
			"port":      rule.ServerPort,
			"type":      rule.Type,
		}).Warn("failed to remove firewall rule from iptables during delete")
		// Continue with database deletion even if iptables removal fails
		// The rule should still be removed from database to keep them in sync
	} else {
		// Log successful removal with clear indication of what happened
		if rule.Type == models.FirewallRuleTypeBlock {
			log.WithFields(log.Fields{
				"rule_id":   rule.ID,
				"remote_ip": rule.RemoteIP,
				"port":      rule.ServerPort,
			}).Info("firewall block rule removed - IP is now unblocked")
		} else {
			log.WithFields(log.Fields{
				"rule_id":   rule.ID,
				"remote_ip": rule.RemoteIP,
				"port":      rule.ServerPort,
			}).Info("firewall allow rule removed - default firewall behavior will apply")
		}
	}

	// Delete from database (soft delete)
	if err := database.Instance().Delete(&rule).Error; err != nil {
		return errors.Wrap(err, "failed to delete firewall rule from database")
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
			// Remove from iptables (lock already held, use unlocked version)
			if err := m.removeRuleUnlocked(&rule); err != nil {
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
