# KeyServ

SSH key-based authentication for IRC.
Because everyone has them. And passwords are annoying.

## Setup
1. Configure InspIRCd oper credentials
2. Edit config.toml to your liking
3. Run `go run .` to start the server

## Features

- Store SSH public keys associated with IRC nicknames
- Authenticate users via SSH keys
- Simple chat commandinterface

## Commands
- `auth [<ssh-key> [name]]` - Register (new) or authenticate (existing)
- `add <ssh-key> [name]` - Add another key (requires auth)
- `remove <fingerprint>` - Remove a key (requires auth)
- `keys` - List your keys (requires auth)
- `whoami` - Check your authentication status
- `info <nick>` - Check if a nickname is registered
- `version` - Show bot version
- `help` - Show the help message

## Support / Community

Questions? Want to chat? Join us at [chat.micr0.dev](https://chat.micr0.dev)

Channels: #dev for project discussion, #help for support

IRC: irc.micr0.dev (ports 6667/6697)
