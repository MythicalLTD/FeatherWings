package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/apex/log"
	"github.com/charmbracelet/huh"
	"github.com/goccy/go-json"
	"github.com/spf13/cobra"

	"github.com/mythicalltd/featherwings/internal/diagnostics"
	"github.com/mythicalltd/featherwings/loggers/cli"
)

const (
	DefaultMclogsAPIURL = "https://api.mclo.gs/1/log"
	DefaultLogLines     = 200
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

	command.Flags().StringVar(&diagnosticsArgs.MclogsURL, "mclogs-api-url", DefaultMclogsAPIURL, "the mclo.gs API endpoint to use for uploads")
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

	u, err := uploadToMclogs(diagnosticsArgs.MclogsURL, report)
	if err == nil {
		fmt.Println("Your report is available here: ", u)
	}
}

type mclogsUploadResponse struct {
	Success bool   `json:"success"`
	ID      string `json:"id"`
	URL     string `json:"url"`
	Raw     string `json:"raw"`
	Error   string `json:"error"`
}

func uploadToMclogs(apiURL, content string) (string, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", err
	}

	formData := new(bytes.Buffer)
	formWriter := multipart.NewWriter(formData)
	formWriter.WriteField("content", content)
	formWriter.Close()

	res, err := http.Post(u.String(), formWriter.FormDataContentType(), formData)
	if err != nil {
		fmt.Println("Failed to upload report to", u.String(), err)
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Failed to parse response.", err)
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		fmt.Println("Failed to upload report to", u.String(), "status:", res.Status)
		fmt.Println(string(body))
		return "", fmt.Errorf("upload failed with status %s", res.Status)
	}

	var uploadResponse mclogsUploadResponse
	if err := json.Unmarshal(body, &uploadResponse); err != nil {
		fmt.Println("Failed to decode response.", err)
		return "", err
	}

	if !uploadResponse.Success {
		if uploadResponse.Error != "" {
			return "", errors.New(uploadResponse.Error)
		}
		return "", errors.New("mclogs upload failed")
	}

	if uploadResponse.URL == "" {
		return "", errors.New("mclogs response missing URL")
	}

	return uploadResponse.URL, nil
}
