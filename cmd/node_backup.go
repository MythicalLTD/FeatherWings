package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/spf13/cobra"

	"github.com/mythicalltd/featherwings/loggers/cli"
	"github.com/mythicalltd/featherwings/system/nodebackup"
)

func newNodeBackupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node-backup",
		Short: "Create, list, restore, and migrate whole-node Wings backups.",
		Long: `Manage node-level FeatherWings backups stored under system.node_backup_directory
(default /var/lib/featherpanel/wings_backup). Prefer stopping the featherwings
service before full or volumes backups for consistent archives.`,
	}
	cmd.AddCommand(newNodeBackupCreateCommand())
	cmd.AddCommand(newNodeBackupListCommand())
	cmd.AddCommand(newNodeBackupRestoreCommand())
	cmd.AddCommand(newNodeBackupDeleteCommand())
	cmd.AddCommand(newNodeBackupExportCommand())
	cmd.AddCommand(newNodeBackupImportCommand())
	return cmd
}

func nodeBackupPreRun(cmd *cobra.Command, _ []string) {
	initConfig()
	log.SetHandler(cli.Default)
}

func newNodeBackupCreateCommand() *cobra.Command {
	var mode string
	cmd := &cobra.Command{
		Use:    "create",
		Short:  "Create a local node backup archive",
		PreRun: nodeBackupPreRun,
		Run: func(cmd *cobra.Command, args []string) {
			m, err := nodebackup.ValidateMode(mode)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			info, err := nodebackup.NewPending(m, false)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("Creating node backup %s (mode=%s)...\n", info.UUID, info.Mode)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
			defer cancel()
			if err := nodebackup.Create(ctx, info); err != nil {
				fmt.Fprintln(os.Stderr, "failed:", err)
				os.Exit(1)
			}
			fmt.Printf("Completed: %s (%d bytes)\n", info.Path, info.Bytes)
		},
	}
	cmd.Flags().StringVar(&mode, "mode", string(nodebackup.ModeVolumes), "volumes | full | user_backups_only")
	return cmd
}

func newNodeBackupListCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "list",
		Short:  "List local node backups",
		PreRun: nodeBackupPreRun,
		Run: func(cmd *cobra.Command, args []string) {
			list, err := nodebackup.List()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if len(list) == 0 {
				fmt.Println("No node backups found.")
				return
			}
			for _, b := range list {
				fmt.Printf("%s  %-18s  %-10s  %10d  %s\n",
					b.UUID, b.Mode, b.Status, b.Bytes, b.CreatedAt.Format(time.RFC3339))
			}
		},
	}
}

func newNodeBackupRestoreCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "restore [uuid]",
		Short:  "Restore a local node backup by UUID",
		Args:   cobra.ExactArgs(1),
		PreRun: nodeBackupPreRun,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
			defer cancel()
			if err := nodebackup.Restore(ctx, args[0]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("Restore completed. Restart featherwings to apply config changes.")
		},
	}
}

func newNodeBackupDeleteCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "delete [uuid]",
		Short:  "Delete a local node backup",
		Args:   cobra.ExactArgs(1),
		PreRun: nodeBackupPreRun,
		Run: func(cmd *cobra.Command, args []string) {
			if err := nodebackup.Delete(args[0]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("Deleted", args[0])
		},
	}
}

func newNodeBackupExportCommand() *cobra.Command {
	var outDir string
	cmd := &cobra.Command{
		Use:    "export",
		Short:  "Create a migration package (full mode)",
		PreRun: nodeBackupPreRun,
		Run: func(cmd *cobra.Command, args []string) {
			info, err := nodebackup.NewPending(nodebackup.ModeFull, true)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("Creating migration package %s...\n", info.UUID)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
			defer cancel()
			if err := nodebackup.Create(ctx, info); err != nil {
				fmt.Fprintln(os.Stderr, "failed:", err)
				os.Exit(1)
			}
			if outDir != "" {
				if err := os.MkdirAll(outDir, 0o755); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				dest := filepath.Join(outDir, fmt.Sprintf("featherwings_migration_%s.tar.gz", info.CreatedAt.Format("20060102_150405")))
				data, err := os.ReadFile(info.Path)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				if err := os.WriteFile(dest, data, 0o600); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				fmt.Printf("Migration package copied to %s\n", dest)
			}
			fmt.Printf("Completed: %s (%d bytes)\n", info.Path, info.Bytes)
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "/var/lib/featherpanel/wings_migrations", "optional directory to copy a named migration artifact into")
	return cmd
}

func newNodeBackupImportCommand() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:    "import",
		Short:  "Import a migration or backup archive from a file path",
		PreRun: nodeBackupPreRun,
		Run: func(cmd *cobra.Command, args []string) {
			if file == "" {
				fmt.Fprintln(os.Stderr, "--file is required")
				os.Exit(1)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
			defer cancel()
			if err := nodebackup.RestoreFile(ctx, file, nodebackup.ModeFull); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("Import completed. Restart featherwings and verify the node in FeatherPanel.")
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "path to featherwings_*.tar.gz archive")
	return cmd
}
