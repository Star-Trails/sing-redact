package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Star-Trails/sing-redact/internal/audit"
	"github.com/Star-Trails/sing-redact/internal/jsonx"
	"github.com/Star-Trails/sing-redact/internal/output"
	"github.com/Star-Trails/sing-redact/internal/redact"
	"github.com/Star-Trails/sing-redact/internal/report"
)

const (
	Version          = "0.1.0"
	PolicyVersion    = "sing-box 1.14.0 testing"
	PolicyCommit     = "df34f5068b961fe3390a61eb3e773ad9bf4d98e2"
	PolicySchemaDate = "2026-08-31"
	maxInputSize     = 64 << 20
)

type options struct {
	input           string
	output          string
	mode            redact.Mode
	stdin           bool
	stdout          bool
	report          bool
	check           bool
	force           bool
	allowSuspicious bool
	gitleaks        bool
	version         bool
	help            bool
}

type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func New() *App {
	return &App{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

func (a *App) Run(arguments []string) int {
	options, err := parseArguments(arguments)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n\n", err)
		writeUsage(a.Stderr)
		return 2
	}
	if options.help {
		writeUsage(a.Stdout)
		return 0
	}
	if options.version {
		fmt.Fprintf(a.Stdout, "sing-redact %s\npolicy: %s / commit %s\npolicy date: %s\n", Version, PolicyVersion, PolicyCommit[:12], PolicySchemaDate)
		return 0
	}
	input, err := a.readInput(options)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return 2
	}
	root, err := jsonx.Parse(input)
	if err != nil {
		fmt.Fprintln(a.Stderr, "error: invalid sing-box JSON syntax; input content was not printed")
		return 2
	}
	engine, err := redact.NewEngine()
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: initialize embedded policy: %v\n", err)
		return 2
	}
	operations, err := engine.Plan(root, options.mode)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: analyze configuration: %v\n", err)
		return 2
	}
	if options.check {
		originalAudit := audit.Scan(root, string(options.mode))
		redactions, applyErr := redact.Apply(root, operations)
		if applyErr != nil {
			fmt.Fprintf(a.Stderr, "error: analyze configuration: %v\n", applyErr)
			return 2
		}
		findings := report.Dedupe(append(redactions, originalAudit...))
		report.WriteCheck(a.Stdout, findings)
		if len(findings) > 0 {
			return 1
		}
		return 0
	}
	redactions, err := redact.Apply(root, operations)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: redact configuration: %v\n", err)
		return 2
	}
	sanitized, err := root.MarshalIndent()
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: serialize sanitized configuration: %v\n", err)
		return 2
	}
	auditFindings := audit.Scan(root, string(options.mode))
	if options.gitleaks {
		additional, gitleaksErr := runGitleaks(sanitized)
		if gitleaksErr != nil {
			fmt.Fprintf(a.Stderr, "error: optional gitleaks audit failed without exposing subprocess output: %v\n", gitleaksErr)
			return 2
		}
		auditFindings = append(auditFindings, additional...)
	}
	auditFindings = report.Dedupe(auditFindings)
	if len(auditFindings) > 0 {
		report.WriteAudit(a.Stderr, "Sanitized-output audit found", auditFindings)
		if !options.allowSuspicious {
			fmt.Fprintln(a.Stderr, "error: sanitized output was not written; inspect the paths or use --allow-suspicious to accept the risk")
			return 3
		}
		fmt.Fprintln(a.Stderr, "warning: continuing because --allow-suspicious was specified")
	}
	if options.report {
		report.WriteRedactions(a.Stderr, redactions)
	}
	if options.stdout {
		if _, err = a.Stdout.Write(sanitized); err != nil {
			fmt.Fprintf(a.Stderr, "error: write sanitized JSON to stdout: %v\n", err)
			return 2
		}
		return 0
	}
	target, err := outputPath(options)
	if err != nil {
		fmt.Fprintf(a.Stderr, "error: %v\n", err)
		return 2
	}
	if err = output.WriteAtomic(target, sanitized, options.force); err != nil {
		if errors.Is(err, output.ErrTargetExists) {
			fmt.Fprintf(a.Stderr, "error: output file already exists: %s (use --force to replace it)\n", target)
		} else {
			fmt.Fprintf(a.Stderr, "error: write output file %s: %v\n", target, err)
		}
		return 2
	}
	fmt.Fprintf(a.Stderr, "Wrote %s\n", target)
	return 0
}

func (a *App) readInput(options options) ([]byte, error) {
	var reader io.Reader
	if options.stdin {
		reader = a.Stdin
	} else {
		file, err := os.Open(options.input)
		if err != nil {
			return nil, fmt.Errorf("open input file %s: %w", options.input, err)
		}
		defer file.Close()
		reader = file
	}
	limited := io.LimitReader(reader, maxInputSize+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if len(content) > maxInputSize {
		return nil, fmt.Errorf("input exceeds %d MiB safety limit", maxInputSize>>20)
	}
	return content, nil
}

func parseArguments(arguments []string) (options, error) {
	result := options{mode: redact.ModeShare}
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch argument {
		case "-h", "--help":
			result.help = true
		case "--version":
			result.version = true
		case "--stdin":
			result.stdin = true
		case "--stdout":
			result.stdout = true
		case "--report":
			result.report = true
		case "--check":
			result.check = true
		case "--force":
			result.force = true
		case "--allow-suspicious":
			result.allowSuspicious = true
		case "--gitleaks":
			result.gitleaks = true
		case "-o", "--output":
			index++
			if index >= len(arguments) {
				return result, errors.New("missing path after --output")
			}
			result.output = arguments[index]
		case "--mode":
			index++
			if index >= len(arguments) {
				return result, errors.New("missing value after --mode")
			}
			mode, err := redact.ParseMode(arguments[index])
			if err != nil {
				return result, err
			}
			result.mode = mode
		default:
			if strings.HasPrefix(argument, "--mode=") {
				mode, err := redact.ParseMode(strings.TrimPrefix(argument, "--mode="))
				if err != nil {
					return result, err
				}
				result.mode = mode
			} else if strings.HasPrefix(argument, "--output=") {
				result.output = strings.TrimPrefix(argument, "--output=")
			} else if strings.HasPrefix(argument, "-") {
				return result, fmt.Errorf("unknown option %s", argument)
			} else if result.input == "" {
				result.input = argument
			} else {
				return result, errors.New("only one input configuration is supported")
			}
		}
	}
	if result.help || result.version {
		return result, nil
	}
	if result.stdin && result.input != "" {
		return result, errors.New("use either an input file or --stdin, not both")
	}
	if !result.stdin && result.input == "" {
		return result, errors.New("missing input configuration path")
	}
	if result.stdout && result.output != "" {
		return result, errors.New("--stdout and --output cannot be combined")
	}
	if result.check && (result.stdout || result.output != "" || result.force) {
		return result, errors.New("--check does not write output; remove --stdout, --output, and --force")
	}
	if result.stdin && result.output == "" && !result.check {
		result.stdout = true
	}
	if result.force && result.stdout {
		return result, errors.New("--force is only valid for file output")
	}
	return result, nil
}

func outputPath(options options) (string, error) {
	target := options.output
	if target == "" {
		extension := filepath.Ext(options.input)
		base := strings.TrimSuffix(options.input, extension)
		target = base + ".redacted.json"
	}
	inputAbsolute, err := filepath.Abs(options.input)
	if err != nil {
		return "", fmt.Errorf("resolve input path: %w", err)
	}
	targetAbsolute, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	if samePath(inputAbsolute, targetAbsolute) {
		return "", errors.New("output path must not be the original configuration")
	}
	return target, nil
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func binaryName() string {
	if len(os.Args) > 0 && os.Args[0] != "" {
		base := filepath.Base(os.Args[0])
		if base != "" && base != "." {
			return base
		}
	}
	if runtime.GOOS == "windows" {
		return "sing-redact.exe"
	}
	return "sing-redact"
}

func writeUsage(writer io.Writer) {
	bin := binaryName()
	fmt.Fprintf(writer, `sing-redact - local, schema-aware sing-box configuration redaction

Usage:
  %s config.json [options]
  %s --stdin [--stdout | -o safe.json]
  %s --version

Options:
  -o, --output PATH       Write to PATH (default: <name>.redacted.json)
      --stdout            Write only sanitized JSON to stdout
      --stdin             Read configuration from stdin
      --mode MODE         credentials, share (default), or strict
      --report            Print redacted categories and JSON paths to stderr
      --check             Analyze only; exit 1 when sensitive data is found
      --force             Atomically replace an existing output file
      --allow-suspicious  Write despite safe-path-only audit findings
      --gitleaks          Run optional local gitleaks audit when installed
  -h, --help              Show this help
      --version           Show tool and policy versions
`, bin, bin, bin)
}

type gitleaksFinding struct {
	RuleID    string `json:"RuleID"`
	StartLine int    `json:"StartLine"`
}

func runGitleaks(content []byte) ([]report.Finding, error) {
	executable, err := exec.LookPath("gitleaks")
	if err != nil {
		return nil, errors.New("gitleaks was not found in PATH")
	}
	directory, err := os.MkdirTemp("", "sing-redact-gitleaks-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	sourceDirectory := filepath.Join(directory, "source")
	if err = os.Mkdir(sourceDirectory, 0o700); err != nil {
		return nil, err
	}
	sourcePath := filepath.Join(sourceDirectory, "sanitized.json")
	reportPath := filepath.Join(directory, "report.json")
	if err = os.WriteFile(sourcePath, content, 0o600); err != nil {
		return nil, err
	}
	command := exec.Command(executable, "detect", "--no-git", "--source", sourceDirectory, "--report-format", "json", "--report-path", reportPath, "--redact", "--no-banner")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	runErr := command.Run()
	if runErr != nil {
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) || exitError.ExitCode() != 1 {
			return nil, errors.New("gitleaks returned a runtime error")
		}
	}
	reportContent, err := os.ReadFile(reportPath)
	if errors.Is(err, os.ErrNotExist) && runErr == nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var raw []gitleaksFinding
	if err = json.Unmarshal(reportContent, &raw); err != nil {
		return nil, errors.New("gitleaks returned an unreadable report")
	}
	findings := make([]report.Finding, 0, len(raw))
	for _, finding := range raw {
		category := "GITLEAKS"
		if finding.RuleID != "" {
			category = "GITLEAKS_" + strings.ToUpper(strings.ReplaceAll(finding.RuleID, "-", "_"))
		}
		findings = append(findings, report.Finding{Category: category, Path: "$ (sanitized line " + strconv.Itoa(finding.StartLine) + ")"})
	}
	return findings, nil
}
