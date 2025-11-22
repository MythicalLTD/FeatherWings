package config

import (
	"fmt"
	"os"
	"strings"

	"emperror.dev/errors"

	"gopkg.in/yaml.v3"
)

// ReadRawConfig reads the configuration file as raw YAML text, preserving comments.
func ReadRawConfig(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "config: failed to read config file")
	}
	return b, nil
}

// WriteRawConfig writes raw YAML content to the configuration file.
func WriteRawConfig(path string, content []byte) error {
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return errors.Wrap(err, "config: failed to write config file")
	}
	return nil
}

// MergeConfigWithRaw merges a Configuration struct with raw YAML content,
// preserving comments from the original file while updating values.
// This function parses the raw YAML as a node tree, updates values, and writes back.
func MergeConfigWithRaw(rawYAML []byte, cfg *Configuration) ([]byte, error) {
	// Parse the raw YAML into a node tree to preserve structure and comments
	var rootNode yaml.Node
	if err := yaml.Unmarshal(rawYAML, &rootNode); err != nil {
		// If parsing fails, fall back to marshaling the struct
		return yaml.Marshal(cfg)
	}

	// Marshal the configuration struct to get updated values
	updatedBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "config: failed to marshal updated config")
	}

	var updatedNode yaml.Node
	if err := yaml.Unmarshal(updatedBytes, &updatedNode); err != nil {
		return nil, errors.Wrap(err, "config: failed to parse updated config")
	}

	// Merge the updated values into the original node tree while preserving comments
	mergeNodes(&rootNode, &updatedNode)

	// Marshal back to YAML with comments preserved
	result, err := yaml.Marshal(&rootNode)
	if err != nil {
		return nil, errors.Wrap(err, "config: failed to marshal merged config")
	}

	return result, nil
}

// mergeNodes recursively merges updatedNode values into rootNode while preserving
// comments and structure from rootNode.
func mergeNodes(rootNode, updatedNode *yaml.Node) {
	if rootNode == nil || updatedNode == nil {
		return
	}

	// If both are mapping nodes, merge their content
	if rootNode.Kind == yaml.MappingNode && updatedNode.Kind == yaml.MappingNode {
		// Create a map of keys to updated values for quick lookup
		updatedMap := make(map[string]*yaml.Node)
		for i := 0; i < len(updatedNode.Content); i += 2 {
			if i+1 < len(updatedNode.Content) {
				key := updatedNode.Content[i].Value
				updatedMap[key] = updatedNode.Content[i+1]
			}
		}

		// Update rootNode content with new values while preserving structure
		for i := 0; i < len(rootNode.Content); i += 2 {
			if i+1 < len(rootNode.Content) {
				keyNode := rootNode.Content[i]
				valueNode := rootNode.Content[i+1]
				key := keyNode.Value

				if updatedValue, exists := updatedMap[key]; exists {
					// If the value is also a mapping or sequence, recurse
					if valueNode.Kind == yaml.MappingNode && updatedValue.Kind == yaml.MappingNode {
						mergeNodes(valueNode, updatedValue)
					} else if valueNode.Kind == yaml.SequenceNode && updatedValue.Kind == yaml.SequenceNode {
						// For sequences, replace the content but keep comments
						valueNode.Content = updatedValue.Content
					} else {
						// For scalar values, update the value but keep comments
						valueNode.Value = updatedValue.Value
						valueNode.Tag = updatedValue.Tag
					}
					delete(updatedMap, key)
				}
			}
		}

		// Add any new keys that weren't in the original
		for key, value := range updatedMap {
			keyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: key,
			}
			rootNode.Content = append(rootNode.Content, keyNode, value)
		}
	} else if rootNode.Kind == yaml.SequenceNode && updatedNode.Kind == yaml.SequenceNode {
		// For sequences, update content but preserve comments
		rootNode.Content = updatedNode.Content
	} else if rootNode.Kind == yaml.ScalarNode && updatedNode.Kind == yaml.ScalarNode {
		// For scalars, update value but preserve comments
		rootNode.Value = updatedNode.Value
		rootNode.Tag = updatedNode.Tag
	}
}

// WriteConfigWithComments writes the configuration to disk while preserving comments
// from the original file. If no original file exists or merging fails, it falls back
// to standard marshaling.
func WriteConfigWithComments(cfg *Configuration) error {
	if cfg.path == "" {
		return errors.New("cannot write configuration, no path defined in struct")
	}

	// Try to read existing file to preserve comments
	rawYAML, err := ReadRawConfig(cfg.path)
	if err != nil && !os.IsNotExist(err) {
		// If read fails for reasons other than file not existing, fall back
		return WriteToDisk(cfg)
	}

	// If file exists, try to merge with comments
	if err == nil {
		merged, mergeErr := MergeConfigWithRaw(rawYAML, cfg)
		if mergeErr == nil {
			return WriteRawConfig(cfg.path, merged)
		}
		// If merge fails, fall back to standard write
	}

	// Fall back to standard write (no comments preserved)
	return WriteToDisk(cfg)
}

// UpdateYAMLNode updates a YAML node tree using dot-notation paths.
// This preserves comments and formatting while updating specific values.
func UpdateYAMLNode(rootNode *yaml.Node, path string, value interface{}) error {
	if rootNode == nil {
		return errors.New("root node is nil")
	}

	parts := strings.Split(path, ".")
	return updateNodeAtPath(rootNode, parts, value)
}

// updateNodeAtPath recursively navigates the YAML node tree and updates the value at the given path.
func updateNodeAtPath(node *yaml.Node, pathParts []string, value interface{}) error {
	if len(pathParts) == 0 {
		// We've reached the target - update the value
		return setNodeValue(node, value)
	}

	if node.Kind != yaml.MappingNode {
		return errors.New("path traverses through non-mapping node")
	}

	key := pathParts[0]
	remainingPath := pathParts[1:]

	// Find the key in the mapping
	var valueNode *yaml.Node

	for i := 0; i < len(node.Content); i += 2 {
		if i+1 >= len(node.Content) {
			break
		}
		keyNode := node.Content[i]
		if keyNode.Value == key {
			valueNode = node.Content[i+1]
			break
		}
	}

	// If key doesn't exist, create it
	if valueNode == nil {
		// Create new key and value nodes
		keyNode := &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: key,
		}

		if len(remainingPath) > 0 {
			// Need to create nested mapping
			valueNode = &yaml.Node{
				Kind: yaml.MappingNode,
			}
		} else {
			// This is the final value
			valueNode = &yaml.Node{}
			if err := setNodeValue(valueNode, value); err != nil {
				return err
			}
		}

		node.Content = append(node.Content, keyNode, valueNode)
	}

	// If there's more path to traverse, recurse
	if len(remainingPath) > 0 {
		// Ensure the node is a mapping for further traversal
		if valueNode.Kind != yaml.MappingNode {
			// Convert to mapping if needed
			valueNode.Kind = yaml.MappingNode
			valueNode.Content = []*yaml.Node{}
		}
		return updateNodeAtPath(valueNode, remainingPath, value)
	}

	// This is the final value - update it
	return setNodeValue(valueNode, value)
}

// setNodeValue sets the value of a YAML node based on the Go value type.
func setNodeValue(node *yaml.Node, value interface{}) error {
	switch v := value.(type) {
	case string:
		node.Kind = yaml.ScalarNode
		node.Value = v
		node.Tag = "!!str"
	case int, int8, int16, int32, int64:
		node.Kind = yaml.ScalarNode
		node.Value = fmt.Sprintf("%d", v)
		node.Tag = "!!int"
	case uint, uint8, uint16, uint32, uint64:
		node.Kind = yaml.ScalarNode
		node.Value = fmt.Sprintf("%d", v)
		node.Tag = "!!int"
	case float32, float64:
		node.Kind = yaml.ScalarNode
		node.Value = fmt.Sprintf("%g", v)
		node.Tag = "!!float"
	case bool:
		node.Kind = yaml.ScalarNode
		if v {
			node.Value = "true"
		} else {
			node.Value = "false"
		}
		node.Tag = "!!bool"
	case []interface{}:
		// Array/slice
		node.Kind = yaml.SequenceNode
		node.Content = make([]*yaml.Node, len(v))
		for i, item := range v {
			itemNode := &yaml.Node{}
			if err := setNodeValue(itemNode, item); err != nil {
				return err
			}
			node.Content[i] = itemNode
		}
	case map[string]interface{}:
		// Map/object
		node.Kind = yaml.MappingNode
		node.Content = make([]*yaml.Node, 0, len(v)*2)
		for k, val := range v {
			keyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: k,
			}
			valNode := &yaml.Node{}
			if err := setNodeValue(valNode, val); err != nil {
				return err
			}
			node.Content = append(node.Content, keyNode, valNode)
		}
	case nil:
		node.Kind = yaml.ScalarNode
		node.Value = "null"
		node.Tag = "!!null"
	default:
		// Try to convert to string as fallback
		node.Kind = yaml.ScalarNode
		node.Value = fmt.Sprintf("%v", v)
		node.Tag = "!!str"
	}
	return nil
}
