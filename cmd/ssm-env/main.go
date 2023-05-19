package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"syscall"

	"io"
	"mime/multipart"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var VersionString string
var procfileRegex = regexp.MustCompile(`^([A-Za-z0-9_\-]+):\s*(.+)$`)

const (
	AppRunError        = -(iota)
	RunCommandError    = -(iota)
	ValidateArgsError  = -(iota)
	GetParametersError = -(iota)
)

type BugsnagParams struct {
	shouldSendDumps bool
	apiKey          string
	dumpsRootPath   string
	bugsnagUrl      string
}

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	app := cli.NewApp()
	app.Name = "ssm-env"
	app.Usage = "Application entry-point that injects SSM Parameter Store values as Environment Variables"
	app.UsageText = "ssm-env [global options] -p prefix command [command arguments]"
	app.Version = VersionString
	app.Flags = cliFlags()
	app.Action = func(c *cli.Context) error {
		return action(c)
	}
	if err := app.Run(os.Args); err != nil {
		_ = cli.NewExitError(errorPrefix(err), AppRunError)
	}
}

func action(c *cli.Context) error {
	if c.GlobalBool("debug") {
		log.SetLevel(log.DebugLevel)
	}
	if c.GlobalBool("silent") {
		log.SetOutput(ioutil.Discard)
	} else {
		log.SetOutput(os.Stdout)
	}

	if err := validateArgs(c); err != nil {
		return cli.NewExitError(errorPrefix(err), ValidateArgsError)
	}

	if !c.GlobalBool("test") {
		if err := getParameters(c); err != nil {
			return cli.NewExitError(errorPrefix(err), GetParametersError)
		}
	}

	return runCommand(c)
}

func cliFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringSliceFlag{
			Name:   "prefix, p",
			Usage:  "Key prefix that is used to retrieve the environment variables - supports multiple use",
			EnvVar: "PARAMS_PREFIX",
		},
		cli.BoolFlag{
			Name:   "debug",
			Usage:  "Log additional debugging information",
			EnvVar: "PARAMS_DEBUG",
		},
		cli.BoolFlag{
			Name:   "silent",
			Usage:  "Silence all logs",
			EnvVar: "PARAMS_SILENT",
		},
		cli.BoolFlag{
			Name:   "long-env-name",
			Usage:  "Use full key path as env name",
			EnvVar: "LONG_ENV_NAME",
		},
		cli.StringFlag{
			Name:   "procfile",
			Usage:  "Path to procfile to use",
			EnvVar: "PROCFILE",
		},
		cli.BoolFlag{
			Name:   "test",
			Usage:  "When running in test mode ssm-env will only launch the target app and will not attempt to read env from SSM",
			EnvVar: "SSM_ENV_TEST",
		},
		cli.BoolFlag{
			Name:   "no-expand",
			Usage:  "ssm-env will not expand environment variables, to expand env VALUE must start from dollar ($) sign, for example HOME=$USER or HOME=${USER}",
			EnvVar: "NO_EXPAND",
		},
		cli.BoolFlag{
			Name:   "uploadDump",
			Usage:  "Upload core dump when the child process gets signaled",
			EnvVar: "UPLOAD_DUMP",
		},
		cli.StringSliceFlag{
			Name:   "bugsnagApiKey",
			Usage:  "Bugsnag API key",
			EnvVar: "BUGSNAG_API_KEY",
		},
		cli.StringSliceFlag{
			Name:   "dumpSearchPath",
			Usage:  "Path for core dumps",
			EnvVar: "DUMP_SEARCH_PATH",
		},
		cli.StringSliceFlag{
			Name:   "bugsnagUrl",
			Usage:  "Path for core dumps",
			EnvVar: "BUGSNAG_URL",
		},
	}
}

func extractBugsnagParams(c *cli.Context) BugsnagParams {
	return BugsnagParams{
		shouldSendDumps: c.GlobalBool("uploadDump"),
		apiKey:          c.GlobalString("bugsnagApiKey"),
		dumpsRootPath:   c.GlobalString("dumpSearchPath"),
		bugsnagUrl:      c.GlobalString("bugsnagUrl"),
	}
}

func errorPrefix(err error) string {
	return strings.Join([]string{"ERROR:", err.Error()}, " ")
}

func escapeEnvVar(str string) string {
	if str == "$" {
		return "$"
	}

	return os.Getenv(str)
}

func getParameters(c *cli.Context) error {
	ctx := context.TODO()
	longFileName := c.GlobalBool("long-env-name")

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
		return err
	}
	svc := ssm.NewFromConfig(cfg)
	for _, prefix := range c.GlobalStringSlice("prefix") {
		parameters, err := getAllParametersByPath(ctx, svc, prefix)
		if err != nil {
			log.Fatalf("error loading SSM params, %v", err)
			return err
		}
		for _, v := range parameters {
			varName := path.Base(*v.Name)
			if longFileName {
				longKeyName := strings.Replace(*v.Name, strings.TrimSuffix(prefix, "/")+"/", "", 1)
				dir := path.Dir(longKeyName)
				if dir != "." {
					varName = strings.ReplaceAll(strings.ToUpper(path.Dir(longKeyName)), "/", "_") + "_" + varName
				}
			}
			if err := os.Setenv(varName, *v.Value); err != nil {
				return err
			}
		}
	}

	if !c.GlobalBool("no-expand") {
		for _, e := range os.Environ() {
			pair := strings.SplitN(e, "=", 2)
			if err := os.Setenv(pair[0], os.Expand(pair[1], escapeEnvVar)); err != nil {
				log.Fatalf("error setting env params, %v", err)
				return err
			}
		}
	}
	return nil
}

func getAllParametersByPath(ctx context.Context, client *ssm.Client, path string) ([]types.Parameter, error) {
	var nextToken *string
	var params []types.Parameter
	var withDecryption bool = true

	input := ssm.GetParametersByPathInput{
		Path:           &path,
		WithDecryption: &withDecryption,
	}

	for ok := true; ok; ok = nextToken != nil {
		input.NextToken = nextToken
		result, err := client.GetParametersByPath(ctx, &input)
		if err != nil {
			return nil, err
		}
		params = append(params, result.Parameters...)
		nextToken = result.NextToken
	}

	return params, nil
}

func validateArgs(c *cli.Context) error {
	if len(c.GlobalStringSlice("prefix")) == 0 {
		return errors.New("prefix is required")
	}

	if c.GlobalBool("uploadDump") {
		errorMessage := ""

		if len(c.GlobalString("bugsnagApiKey")) == 0 {
			errorMessage = "an API key is required for Bugsnag reporting"
		}
		if len(c.GlobalString("dumpSearchPath")) == 0 {
			errorMessage += "\nWe need dumpSearchPath to know where the dump is"
		}
		if len(c.GlobalString("bugsnagUrl")) == 0 {
			errorMessage += "\nWe need bugsnagUrl to know where to send the dump"
		}

		if len(errorMessage) > 0 {
			return errors.New(errorMessage)
		}
	}

	if c.NArg() == 0 {
		return errors.New("command not specified")
	}

	return nil
}

func locateDump(rootDirectory string) (result string, err error) {
	findCommand := exec.Command("find", rootDirectory, "-name", "core.*")
	executionResult, err := findCommand.CombinedOutput()

	if err == nil {
		if len(executionResult) > 0 {
			result = strings.Split(string(executionResult), "\n")[0]
		} else {
			err = fmt.Errorf("found 0 dumps at the specified location")
		}
	} else {
		err = fmt.Errorf("an error occurre while searching for the dump: %w;\noutput: %s", err, string(executionResult))
	}

	return result, err
}

func sendFile(fieldName string, filePath string, url string) (result string, err error) {
	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)

	errorsChannel := make(chan error, 1)

	go writeMultipartToPipe(pipeWriter, fieldName, filePath, multipartWriter, errorsChannel)

	response, err := http.Post(url, multipartWriter.FormDataContentType(), pipeReader)
	writingError := <-errorsChannel

	if err == nil && writingError == nil {
		defer response.Body.Close()
		var responseBody []byte

		if err == nil {
			responseBody, err = io.ReadAll(response.Body)
			result = string(responseBody)
		}

		if response.StatusCode != 202 {
			if err != nil {
				err = fmt.Errorf("unexpected response code: %d;\nAnd also: %w", response.StatusCode, err)
			} else {
				err = fmt.Errorf("unexpected response code: %d", response.StatusCode)
			}
		}
	} else {
		if err == nil {
			err = writingError
		} else if writingError != nil {
			err = fmt.Errorf("%w; %w", err, writingError)
		}
	}

	return result, err
}

func writeMultipartToPipe(targetPipe *io.PipeWriter, fieldName string, filePath string, multipartWriter *multipart.Writer, errorChannel chan<- error) {
	file, fileInfo, err := openFile(filePath)

	defer targetPipe.Close()
	defer file.Close()

	if err == nil {
		var formFileWriter io.Writer

		if formFileWriter, err = multipartWriter.CreateFormFile(fieldName, fileInfo.Name()); err == nil {
			if _, err = io.Copy(formFileWriter, file); err == nil {
				err = multipartWriter.Close()
			}
		}
	}

	errorChannel <- err
}

func openFile(path string) (file *os.File, fileInfo os.FileInfo, err error) {
	if file, err = os.Open(path); err == nil {
		fileInfo, err = file.Stat()
	}

	return file, fileInfo, err
}

func invoke(command string, args []string, bugsnagParams BugsnagParams) error {
	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// in order to make sure that we catch and propagate signals correctly, we need
	// to decouple starting the command and waiting for it to complete, so we can
	// send signals as it runs
	if err := cmd.Start(); err != nil {
		log.WithError(err).Error("failed to start child process")
		return err
	}

	// wait for the command to finish
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Wait()
		close(errCh)
	}()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGTERM)

	for {
		select {
		case sig := <-sigCh:
			// this error case only seems possible if the OS has released the process
			// or if it isn't started. So we _should_ be able to break
			if err := cmd.Process.Signal(sig); err != nil {
				log.WithError(err).WithField("signal", sig).Error("error sending signal")
				return err
			}
		case err := <-errCh:
			// the command finished.
			if err != nil {
				if exiterr, ok := err.(*exec.ExitError); ok && bugsnagParams.shouldSendDumps {
					if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
						if status.Signaled() && status.Signal() != syscall.SIGINT {
							if dumpLocation, dumpSearchError := locateDump(bugsnagParams.dumpsRootPath); dumpSearchError == nil {
								fileSendResult, fileSendError := sendFile("upload_file_minidump", dumpLocation, fmt.Sprintf("%s/minidump?api_key=%s", bugsnagParams.bugsnagUrl, bugsnagParams.apiKey))
								if fileSendError != nil {
									log.WithError(fileSendError).Error(fmt.Sprintf("Failed to send the core dump. %s", fileSendResult))
								} else {
									log.Info("sent the core dump to Bugsnag")
								}
							} else {
								log.WithError(err).Error("Failed to locate the core dump. %s", dumpSearchError)
							}
						}
					}
				}
				log.WithError(err).Error("command failed")
				return err
			}
			return nil
		}
	}
}

func runCommand(c *cli.Context) error {
	command := c.Args().First()
	procfileName := c.GlobalString("procfile")
	if procfileName == "" {
		procfileName = "Procfile"
	}
	bugsnagParams := extractBugsnagParams(c)

	if _, err := os.Stat(procfileName); os.IsNotExist(err) {
		return invoke(command, c.Args().Tail(), bugsnagParams)
	}

	procContent, err := ioutil.ReadFile(procfileName)

	if err != nil {
		log.Fatalf("unable to read Procfile, %v", err)
		os.Exit(RunCommandError)
	}

	for _, line := range strings.Split(string(procContent), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if matches := procfileRegex.FindStringSubmatch(line); matches != nil {
			name, procCommand := matches[1], matches[2]
			if name == command {
				cmdParts := strings.Split(strings.Trim(procCommand, " "), " ")
				return invoke(cmdParts[0], cmdParts[1:], bugsnagParams)
			}
		}
	}

	return invoke(command, c.Args().Tail(), bugsnagParams)
}
