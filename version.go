package main

import "fmt"

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

func printVersion() {
	fmt.Printf("DNSLeaf %s (commit %s, built %s)\n", version, commit, buildDate)
}

func printUsage() {
	fmt.Println("DNSLeaf - self-hosted DNS resolver and network policy manager")
	fmt.Println("usage: dnsleaf [--config path] [--no-tui] [command]")
	fmt.Println("       dnsleaf --version")
	fmt.Println("commands: validate, user, service")
}
