package common

import (
	"fmt"
	"strings"

	vtypes "github.com/vultisig/verifier/types"
)

// TODO: remove once the plugin installation is implemented (resharding)
const (
	PluginPartyID   = "Rado's MacBook Pro-FD0"
	VerifierPartyID = "Server-58253"
)

func GetSortingCondition(sort string) (string, string) {
	// Default sorting column
	orderBy := "created_at"
	orderDirection := "ASC"

	// Check if sort starts with "-"
	isDescending := strings.HasPrefix(sort, "-")
	columnName := strings.TrimPrefix(sort, "-") // Remove "-" if present

	// Ensure orderBy is a valid column name (prevent SQL injection)
	allowedColumns := map[string]bool{"updated_at": true, "created_at": true, "title": true}
	if allowedColumns[columnName] {
		orderBy = columnName // Use the provided column if valid
	}

	// Apply descending order if necessary
	if isDescending {
		orderDirection = "DESC"
	}

	return orderBy, orderDirection
}

// PolicyToMessageHex converts a plugin policy to a message hex string for signature verification.
// It joins policy fields with a delimiter and validates that no field contains the delimiter.
func PolicyToMessageHex(policy vtypes.PluginPolicy) ([]byte, error) {
	delimiter := "*#*"
	fields := []string{
		policy.Recipe,
		policy.PublicKey,
		fmt.Sprintf("%d", policy.PolicyVersion),
		policy.PluginVersion}
	for _, item := range fields {
		if strings.Contains(item, delimiter) {
			return nil, fmt.Errorf("invalid policy signature")
		}
	}
	result := strings.Join(fields, delimiter)
	return []byte(result), nil
}
