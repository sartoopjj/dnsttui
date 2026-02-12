package components

import (
	"context"
	"fmt"

	"github.com/sartoopjj/dnsttui/internal/database"
)

type contextKey string

const basePathKey contextKey = "basePath"

// WithBasePath stores the panel base path in a context.
func WithBasePath(ctx context.Context, basePath string) context.Context {
	return context.WithValue(ctx, basePathKey, basePath)
}

// BasePathFromContext returns the panel base path from ctx (empty string if unset).
func BasePathFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(basePathKey).(string); ok {
		return v
	}
	return ""
}

// FormatBytes formats bytes into human-readable string.
func FormatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatTrafficLimit formats traffic limit, 0 means unlimited.
func FormatTrafficLimit(b int64) string {
	if b == 0 {
		return "Unlimited"
	}
	return FormatBytes(b)
}

// UserStatusClass returns the CSS class for a user's status badge.
func UserStatusClass(u database.SSUser) string {
	if !u.Enabled {
		return "bg-gray-100 text-gray-800"
	}
	if u.IsExpired() {
		return "bg-red-100 text-red-800"
	}
	if u.IsOverLimit() {
		return "bg-yellow-100 text-yellow-800"
	}
	return "bg-green-100 text-green-800"
}

// UserStatusText returns the status text for a user.
func UserStatusText(u database.SSUser) string {
	if !u.Enabled {
		return "Disabled"
	}
	if u.IsExpired() {
		return "Expired"
	}
	if u.IsOverLimit() {
		return "Over Limit"
	}
	return "Active"
}
