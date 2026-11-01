package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func execute(args []string, i inspector) int {
	flags := flag.NewFlagSet("hardening-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jsonOutput := flags.Bool("json", false, "print JSON result")
	notify := flags.Bool("notify", false, "notify on failure")
	baseline := flags.Bool("write-baseline", false, "save current non-loopback TCP listeners")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		return 2
	}
	if *baseline {
		if err := i.writeBaseline(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Println("Wrote listener baseline:", i.baselinePath())
		return 0
	}
	result := i.inspect()
	if *jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else {
		for _, c := range result.Checks {
			fmt.Printf("%s %s: %s\n", c.Status, c.Name, c.Detail)
		}
		if result.OK {
			fmt.Println("Hardening check: PASS")
		} else {
			fmt.Println("Hardening check: FAIL")
		}
	}
	if !result.OK {
		if *notify {
			var names []string
			for _, c := range result.Checks {
				if c.Status == "FAIL" {
					names = append(names, c.Name)
				}
			}
			_, _ = i.run("notify-send", "-u", "critical", "Hardening check failed", strings.Join(names, ", "))
		}
		return 1
	}
	return 0
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(execute(os.Args[1:], inspector{root: "/", home: home, run: realRunner}))
}
