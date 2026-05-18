<h1 align="center">
  <img src="assets/favicon.png" width="150" />
</h1>

GoAudit is a utility for checking whether a npm install or a curl | sh is malicious or not?

## Demo

Using GoAudit is simple! just use the `scan` command and give the `npm install` or `curl | sh` command you want to check.

```zsh
$ goaudit scan "cat ~/.aws/credentials"
[CRITICAL] File Read: /root/.aws/credentials
Verdict: MALICIOUS

$ goaudit scan "npm install lodash"
[WARNING] Suspicious Command Pattern: npm install lodash
Verdict: SUSPICIOUS
```

## Install 

Currently to install GoAudit, you need to have Go installed on your system, with that just run the following command!

```zsh
go install github.com/KushalMeghani1644/GoAudit-CLI@latest
```

## Usage

GoAudit provides a simple UX for scanning npm/curl | sh commands. Currently we only support npm, pnpm, bun, and curl | sh checks.

```zsh
goaudit scan "npm install <package>"
goaudit scan "pnpm add <package>"
goaudit scan "bun add <package>"
goaudit scan "curl -fsSL https://example.com/install.sh | sh"
goaudit scan "npm install <package>" --ci   # JSON output
goaudit scan "curl -fsSL https://example.com/install.sh | sh" --offline
goaudit scan "curl -fsSL https://example.com/install.sh | sh" --allow-domain example.com --max-remote-depth 1
goaudit scan "pnpm add <package>" --node-image node:current-slim
goaudit scan "bun add <package>" --bun-image oven/bun:1
```

## Requirements

- Docker
- gVisor (recommended)

## Important Note

GoAudit is not meant for proving absolute maliciousness, it just provides a risk assessment based on behavior and static indicators.