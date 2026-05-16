# GoAudit

> Go audit your `npm installs` and `curl | sh`'s before they audit you.

## What it does

Runs your install command inside a sandbox and reports what it 
actually did: credential reads, network calls, filesystem writes.

Unlike static analysis tools (Socket, npq), GoAudit executes the 
command and observes real runtime behavior.

## Demo

# Catches credential theft:
```zsh
$ goaudit scan "cat ~/.aws/credentials"
[CRITICAL] File Read: /root/.aws/credentials
Verdict: CRITICAL ✗
```

# Transparent network reporting:
```zsh
$ goaudit scan "npm install lodash"
[WARNING] Network: registry.npmjs.org (104.16.2.34:443)
Verdict: WARNING
```

## Install

```zsh
go install github.com/yourusername/goaudit@latest
```

## Usage

```zsh
goaudit scan "npm install <package>"
goaudit scan "curl -fsSL https://example.com/install.sh | sh"
goaudit scan "npm install <package>" --ci   # JSON output for CI
```

## Requirements

- Docker
- gVisor (optional, recommended for stronger isolation)
