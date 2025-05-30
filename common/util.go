package common

import (
	"strings"
)

// TODO: remove once the plugin installation is implemented (resharding)
const (
	PluginPartyID   = "Rado’s MacBook Pro-FD0"
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
