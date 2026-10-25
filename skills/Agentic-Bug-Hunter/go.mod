// Canonical Go module path for this repository (matches GitHub's go-import meta).
//
// Release tags v1–v6 were published before this file existed, so the Go module
// proxy recorded them as github.com/shuvonsec/claude-bug-bounty …+incompatible
// (the pre-rename / pre-transfer path). New versions use this path.
//
// Old require lines keep working via the GitHub repo redirect; new consumers
// should depend on github.com/awarexone/Agentic-Bug-Hunter.
module github.com/awarexone/Agentic-Bug-Hunter

go 1.22
