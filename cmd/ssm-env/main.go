package main

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"syscall"

	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var VersionString string
var invalidPattern = regexp.MustCompile(`[^a-zA-Z0-9_]`)
var procfileRegex = regexp.MustCompile(`^([A-Za-z0-9_]+):\s*(.+)$`)

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
	app.Run(os.Args)
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

	code, err := validateArgs(c)
	if code > 0 {
		return cli.NewExitError(errorPrefix(err), code)
	}

	if err := getParameters(c); err != nil {
		return cli.NewExitError(errorPrefix(err), code)
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
	}
}

func errorPrefix(err error) string {
	return strings.Join([]string{"ERROR:", err.Error()}, " ")
}

func getParameters(c *cli.Context) error {
	ctx := context.TODO()
	longFileName := c.GlobalBool("long-env-name")

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	svc := ssm.NewFromConfig(cfg)

	for _, prefix := range c.GlobalStringSlice("prefix") {
		input := ssm.GetParametersByPathInput{
			Path:           &prefix,
			Recursive:      true,
			WithDecryption: true,
		}
		params, err := svc.GetParametersByPath(ctx, &input)
		if err != nil {
			return err
		}

		for _, v := range params.Parameters {
			varName := path.Base(*v.Name)
			if longFileName {
				longKeyName := strings.Replace(*v.Name, strings.TrimSuffix(prefix, "/")+"/", "", 1)
				dir := path.Dir(longKeyName)
				if dir != "." {
					varName = strings.ReplaceAll(strings.ToUpper(path.Dir(longKeyName)), "/", "_") + "_" + varName
				}
			}
			os.Setenv(varName, *v.Value)
		}

	}
	return nil
}

func validateArgs(c *cli.Context) (int, error) {
	if len(c.GlobalStringSlice("prefix")) == 0 {
		return 1, errors.New("prefix is required")
	}

	if c.NArg() == 0 {
		return 2, errors.New("command not specified")
	}

	return 0, nil
}

func invoke(command string, args []string) error {
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
			// this errror case only seems possible if the OS has released the process
			// or if it isn't started. So we _should_ be able to break
			if err := cmd.Process.Signal(sig); err != nil {
				log.WithError(err).WithField("signal", sig).Error("error sending signal")
				return err
			}
		case err := <-errCh:
			// the command finished.
			if err != nil {
				log.WithError(err).Error("command failed")
				return err
			}
			return nil
		}
	}
}

func runCommand(c *cli.Context) error {
	command := c.Args().First()

	if _, err := os.Stat("Procfile"); os.IsNotExist(err) {
		return invoke(command, c.Args().Tail())
	}

	procContent, err := ioutil.ReadFile("Procfile")

	if err != nil {
		log.Fatalf("unable to read Procfile, %v", err)
		panic(err)
	}

	for _, line := range strings.Split(string(procContent), "\n") {
		if matches := procfileRegex.FindStringSubmatch(line); matches != nil {
			name, procCommand := matches[1], matches[2]
			if name == command {
				cmdParts := strings.Split(strings.Trim(procCommand, " "), " ")
				return invoke(cmdParts[0], cmdParts[1:])
			}
		}
	}

	return invoke(command, c.Args().Tail())
}
