# nullsweep

Comprehensive null/anonymous session scanner and enumerator for Active Directory domain controllers.

Single-file Python tool — no Samba dependencies, pure impacket. SCP it to your attack box and go.

## What It Does

1. **Discovers domain controllers** via DNS SRV records
2. **Tests three auth methods** — null session, anonymous logon, guest account — against each DC
3. **Probes three RPC pipes** — SAMR, LSARPC, SRVSVC — per working session
4. **Enumerates everything accessible** — users, machine accounts, groups, shares, password policy, lockout policy, domain trusts
5. **RID cycles with automatic fallback** — tries SAMR enumerate, then SAMR LookupIds, then LSARPC LookupSids

### Why Not Just Use enum4linux / NetExec / lookupsid?

Each tool hits one pipe with one auth method. If that pipe is blocked, the tool fails even though another path might work:

- **enum4linux** uses SAMR via rpcclient — fails when LSARPC is the open path
- **NetExec** `--rid-brute` uses LSARPC — fails when SAMR is the open path
- **lookupsid.py** uses LSARPC only — same limitation
- **samrdump.py** uses SAMR only — no RID cycling fallback

nullsweep tries all three auth methods across all three pipes and uses whatever works.

## Install

```bash
pip install -r requirements.txt
```

Or on Kali (where impacket is already installed):

```bash
pip install dnspython
```

## Usage

```bash
# Discover DCs and test for null/anonymous sessions
python3 nullsweep.py example.com

# Target specific DCs
python3 nullsweep.py example.com --dc dc01.example.com
python3 nullsweep.py example.com --dc-file dcs.txt

# Use a specific DNS server for DC discovery
python3 nullsweep.py example.com --dns-server 10.0.0.1

# RID cycle to enumerate all accounts
python3 nullsweep.py example.com --rid-cycle

# Full dump — users, groups, shares, policy, trusts, RID cycling
python3 nullsweep.py example.com --dump -o ./loot

# Just usernames for password spraying (clean, one per line)
python3 nullsweep.py example.com --rid-cycle --users-only > users.txt

# With credentials instead of null sessions
python3 nullsweep.py example.com --dump -u jsmith -p 'Password1' -o ./loot

# Increase RID range for very large domains
python3 nullsweep.py example.com --dump --max-rid 200000 -o ./loot

# Full line-by-line output to stdout (verbose)
python3 nullsweep.py example.com --dump -v
```

## Output Files

With `-o <dir>`, nullsweep writes categorized output:

| File | Contents |
|------|----------|
| `users.txt` | User accounts (one per line, spray-ready) |
| `computers.txt` | Machine accounts (names with `$` suffix) |
| `service_accounts.txt` | MSA/gMSA accounts (GUID-style names) |
| `groups.txt` | Domain groups |
| `other.txt` | Uncategorized entries (groups with unknown type, etc.) |
| `shares.txt` | Share names, types, and comments |
| `policy.txt` | Password and lockout policy |

## RID Cycling Fallback Chain

nullsweep tries three methods in order and uses the first that works:

1. **SAMR EnumerateUsersInDomain** — complete enumeration, no guessing. Only returns what the session has permission to see (often just normal users via null session).
2. **SAMR LookupIdsInDomain** — RID cycling through the SAMR pipe. Lookup-based, so it returns any object the RID matches, including machine accounts.
3. **LSARPC LookupSids** — RID cycling through the LSA pipe. Same lookup approach, different pipe. Works when SAMR is blocked.

In `--dump` mode, SAMR enumerate runs first for users, then RID cycling always runs to catch machine accounts and anything SAMR enumerate missed. Results are merged and deduplicated.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `domain` | (required) | Target AD domain |
| `--dc HOST` | | Target specific DC (repeatable) |
| `--dc-file FILE` | | Read DC hostnames from file |
| `--dns-server IP` | | DNS server for DC discovery |
| `--rid-cycle` | | RID cycle for account enumeration |
| `--dump` | | Full enumeration dump |
| `--max-rid N` | 100000 | Maximum RID to cycle to |
| `--batch-size N` | 1000 | RIDs per lookup batch (max 1000) |
| `-u` / `-p` | | Username / password for authenticated access |
| `--hashes LM:NT` | | Pass the hash |
| `-o DIR` | | Output directory for result files |
| `--users-only` | | Print only usernames to stdout |
| `-v` / `--verbose` | | Print full listings to stdout |
| `--no-color` | | Disable ANSI color output |
| `--timeout SEC` | 10 | Connection timeout |
| `--debug` | | Debug logging |

## Dependencies

- Python 3.8+
- [impacket](https://github.com/fortra/impacket) >= 0.11.0
- [dnspython](https://github.com/rthalley/dnspython) >= 2.4.0

## License

For authorized security testing only.
