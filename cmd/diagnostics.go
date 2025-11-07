package cmd

import (
	"context"
	"fmt"

	"github.com/apex/log"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/mythicalltd/featherwings/internal/diagnostics"
	"github.com/mythicalltd/featherwings/loggers/cli"
)

const (
	DefaultLogLines = 200
)

var diagnosticsArgs struct {
	IncludeEndpoints   bool
	IncludeLogs        bool
	ReviewBeforeUpload bool
	MclogsURL          string
	LogLines           int
}

func newDiagnosticsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "diagnostics",
		Short: "Collect and report information about this Wings instance to assist in debugging.",
		PreRun: func(cmd *cobra.Command, args []string) {
			initConfig()
			log.SetHandler(cli.Default)
		},
		Run: diagnosticsCmdRun,
	}

	command.Flags().StringVar(&diagnosticsArgs.MclogsURL, "mclogs-api-url", diagnostics.DefaultMclogsAPIURL, "the mclo.gs API endpoint to use for uploads")
	command.Flags().IntVar(&diagnosticsArgs.LogLines, "log-lines", DefaultLogLines, "the number of log lines to include in the report")

	return command
}

// diagnosticsCmdRun collects diagnostics about wings, its configuration and the node.
// We collect:
// - wings and docker versions
// - relevant parts of daemon configuration
// - the docker debug output
// - running docker containers
// - logs
func diagnosticsCmdRun(*cobra.Command, []string) {
	// To set default to true
	defaultTrueConfirmAccessor := func() huh.Accessor[bool] {
		accessor := huh.EmbeddedAccessor[bool]{}
		accessor.Set(true)
		return &accessor
	}
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Do you want to include endpoints (i.e. the FQDN/IP of your panel)?").
				Value(&diagnosticsArgs.IncludeEndpoints),
			huh.NewConfirm().
				Title("Do you want to include the latest logs?").
				Accessor(defaultTrueConfirmAccessor()).
				Value(&diagnosticsArgs.IncludeLogs),
			huh.NewConfirm().
				Title(fmt.Sprintf("Do you want to review the collected data before uploading to %s?", diagnosticsArgs.MclogsURL)).
				Description("The data, especially the logs, might contain sensitive information, so you should review it. You will be asked again if you want to upload.").
				Accessor(defaultTrueConfirmAccessor()).
				Value(&diagnosticsArgs.ReviewBeforeUpload),
		),
	)
	if err := form.Run(); err != nil {
		if err == huh.ErrUserAborted {
			return
		}
		panic(err)
	}

	report, err := diagnostics.GenerateDiagnosticsReport(
		diagnosticsArgs.IncludeEndpoints,
		diagnosticsArgs.IncludeLogs,
		diagnosticsArgs.LogLines,
	)
	if err != nil {
		fmt.Println("Error generating report:", err)
		return
	}

	fmt.Println("\n---------------  generated report  ---------------")
	fmt.Println(report)
	fmt.Print("---------------   end of report    ---------------\n\n")

	if diagnosticsArgs.ReviewBeforeUpload {
		upload := false
		huh.NewConfirm().Title("Upload to " + diagnosticsArgs.MclogsURL + "?").Value(&upload).Run()
		if !upload {
			return
		}
	}

	u, err := diagnostics.UploadReport(context.Background(), diagnosticsArgs.MclogsURL, report)
	if err != nil {
		fmt.Println("Failed to upload report:", err)
		return
	}

	fmt.Println("Your report is available here: ", u)
}
