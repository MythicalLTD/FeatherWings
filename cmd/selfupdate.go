package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/selfupdate"
	"github.com/mythicalltd/featherwings/system"
	"github.com/spf13/cobra"
)

var updateArgs struct {
	repoOwner       string
	repoName        string
	force           bool
	fromURL         string
	sha256          string
	disableChecksum bool
}

func newSelfupdateCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update wings to the latest version",
		Run:   selfupdateCmdRun,
		PreRun: func(cmd *cobra.Command, args []string) {
			initConfig()
		},
	}

	command.Flags().StringVar(&updateArgs.repoOwner, "repo-owner", "", "GitHub repository owner (defaults to system.updates.repo_owner)")
	command.Flags().StringVar(&updateArgs.repoName, "repo-name", "", "GitHub repository name (defaults to system.updates.repo_name)")
	command.Flags().BoolVar(&updateArgs.force, "force", false, "Force update even if on latest version")
	command.Flags().StringVar(&updateArgs.fromURL, "from-url", "", "Direct URL to download the updated wings binary")
	command.Flags().StringVar(&updateArgs.sha256, "from-url-sha256", "", "Expected SHA256 checksum for the --from-url download")
	command.Flags().BoolVar(&updateArgs.disableChecksum, "disable-checksum", false, "Skip checksum verification (use with caution)")

	return command
}

func selfupdateCmdRun(_ *cobra.Command, _ []string) {
	currentVersion := system.Version
	if currentVersion == "" {
		fmt.Println("Error: current version is not defined")
		return
	}

	if currentVersion == "develop" && !updateArgs.force {
		fmt.Println("Running in development mode. Use --force to override.")
		return
	}

	fmt.Printf("Current version: %s\n", currentVersion)

	cfg := config.Get()
	ctx := context.Background()

	repoOwner := updateArgs.repoOwner
	if repoOwner == "" {
		repoOwner = cfg.System.Updates.RepoOwner
	}
	if repoOwner == "" {
		repoOwner = "mythicalltd"
	}

	repoName := updateArgs.repoName
	if repoName == "" {
		repoName = cfg.System.Updates.RepoName
	}
	if repoName == "" {
		repoName = "featherwings"
	}

	preferredBinaryName, err := selfupdate.DetermineBinaryName(cfg.System.Updates.GitHubBinaryTemplate)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	skipChecksumGitHub := cfg.System.Updates.DisableChecksum || updateArgs.disableChecksum
	skipChecksumURL := updateArgs.disableChecksum
	restartCommand := strings.TrimSpace(cfg.System.Updates.RestartCommand)
	notifyRestart := func(assetName string) {
		fmt.Println("\nUpdate successful!")
		if assetName != "" {
			fmt.Printf("Installed asset: %s\n", filepath.Base(assetName))
		}
		if restartCommand != "" {
			fmt.Printf("Executing restart command: %s\n", restartCommand)
			restartCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := selfupdate.RunRestartCommand(restartCtx, restartCommand)
			if output != "" {
				fmt.Println(output)
			}
			if err != nil {
				fmt.Printf("Warning: restart command failed: %v\n", err)
			}
		} else {
			fmt.Println("Please restart the wings service (e.g., systemctl restart wings)")
		}
	}

	downloadURL := updateArgs.fromURL
	if downloadURL == "" {
		downloadURL = cfg.System.Updates.DefaultURL
	}

	if downloadURL != "" {
		if !cfg.System.Updates.EnableURL {
			fmt.Println("URL-based updates are disabled by configuration.")
			return
		}

		checksum := updateArgs.sha256
		if checksum == "" {
			checksum = cfg.System.Updates.DefaultSHA256
		}

		if checksum == "" && !skipChecksumURL {
			fmt.Println("Error: checksum required for --from-url updates (provide --from-url-sha256 or enable --disable-checksum).")
			return
		}

		fmt.Printf("Updating from direct URL: %s\n", downloadURL)
		if err := selfupdate.UpdateFromURL(ctx, downloadURL, preferredBinaryName, checksum, skipChecksumURL); err != nil {
			fmt.Printf("Update failed: %v\n", err)
			return
		}

		notifyRestart("")
		return
	}

	releaseInfo, err := selfupdate.FetchLatestReleaseInfo(ctx, repoOwner, repoName)
	if err != nil {
		fmt.Printf("Failed to fetch latest release metadata: %v\n", err)
		return
	}

	latestVersionTag := releaseInfo.TagName
	if latestVersionTag == "" {
		fmt.Println("Failed to determine latest release tag.")
		return
	}

	currentVersionTag := "v" + currentVersion
	if currentVersion == "develop" {
		currentVersionTag = currentVersion
	}

	if latestVersionTag == currentVersionTag && !updateArgs.force {
		fmt.Printf("You are running the latest version: %s\n", currentVersion)
		return
	}

	fmt.Printf("Updating from %s to %s\n", currentVersionTag, latestVersionTag)

	assetName, err := selfupdate.UpdateFromGitHub(ctx, repoOwner, repoName, releaseInfo, cfg.System.Updates.GitHubBinaryTemplate, skipChecksumGitHub)
	if err != nil {
		fmt.Printf("Update failed: %v\n", err)
		return
	}

	notifyRestart(assetName)
}
