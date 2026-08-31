package main

import (
	"os"

	"github.com/Star-Trails/sing-redact/internal/app"
)

func main() {
	os.Exit(app.New().Run(os.Args[1:]))
}
