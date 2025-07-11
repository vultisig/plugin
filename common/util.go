package common

import (
	"encoding/base64"
	"fmt"
	"strings"

	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
	"google.golang.org/protobuf/proto"
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

// RecipeToBase64 converts a recipe policy to a protobuf-encoded, base64-encoded string.
// This encoded string can be used as the recipe field in a vtypes.PluginPolicy.
func RecipeToBase64(recipe rtypes.Policy) (string, error) {
	// Marshal the recipe to protobuf
	protoBytes, err := proto.Marshal(&recipe)
	if err != nil {
		return "", fmt.Errorf("failed to marshal recipe: %w", err)
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(protoBytes), nil
}
