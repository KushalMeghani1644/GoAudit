package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/KushalMeghani1644/GoAudit-CLI/internal/sandbox"
	"github.com/spf13/cobra"
)

var cacheRuntimeFilter string

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage sandbox cache",
}

var cacheStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cached sandbox containers",
	Run: func(cmd *cobra.Command, args []string) {
		cache, err := sandbox.NewCacheManager(cacheDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer cache.Close()

		entries := cache.Entries()
		if len(entries) == 0 {
			fmt.Println("No cached sandboxes.")
			return
		}

		fmt.Printf("%-20s %-12s %-45s %-20s %-20s\n", "KEY", "RUNTIME", "IMAGE", "CREATED", "LAST USED")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────")
		for key, entry := range entries {
			age := time.Since(entry.CreatedAt).Round(time.Minute)
			lastUsed := time.Since(entry.LastUsed).Round(time.Minute)
			rt := entry.Runtime
			if rt == "" {
				rt = "runc"
			}
			fmt.Printf("%-20s %-12s %-45s %-20s %-20s\n",
				key, rt, entry.Image,
				fmt.Sprintf("%s ago", age),
				fmt.Sprintf("%s ago", lastUsed),
			)
		}
		fmt.Printf("\nCache directory: %s\n", cache.Dir())
	},
}

var cacheCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove cached sandbox containers",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		cache, err := sandbox.NewCacheManager(cacheDir)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		defer cache.Close()

		if cacheRuntimeFilter != "" {
			rt := cacheRuntimeFilter
			if rt == "runc" {
				rt = ""
			}
			cache.InvalidateByRuntime(ctx, rt)
			fmt.Printf("Removed all %s cached sandboxes.\n", cacheRuntimeFilter)
		} else {
			cache.InvalidateAll(ctx)
			fmt.Println("Removed all cached sandboxes.")
		}
	},
}

func init() {
	cacheCmd.PersistentFlags().StringVar(&cacheDir, "cache-dir", "", "Custom directory for sandbox cache (or set GOAUDIT_CACHE_DIR)")
	cacheCleanCmd.Flags().StringVar(&cacheRuntimeFilter, "runtime", "", "Only remove caches for this runtime (runsc or runc)")
	cacheCmd.AddCommand(cacheStatusCmd)
	cacheCmd.AddCommand(cacheCleanCmd)
	rootCmd.AddCommand(cacheCmd)
}
