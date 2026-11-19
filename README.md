# nullsweep

Null/anonymous session scanner and enumerator for Active Directory domain controllers. Single Python file, pure impacket, no Samba dependencies. SCP it to your attack box and go.

## Why This Exists

Every existing tool for null session enumeration hits one RPC pipe with one auth method. If that specific pipe is blocked, the tool fails — even when another path is wide open:

* enum4linux uses SAMR via rpcclient. If LSARPC is the open pipe, it misses it.
* NetExec `--rid-brute` uses LSARPC. If SAMR is open but LSARPC is locked, you get nothing.
* lookupsid.py and samrdump.py have the same single-pipe problem.

nullsweep tries null, anonymous, and guest sessions across SAMR, LSARPC, and SRVSVC. Whatever path is open, it finds it and uses it. RID cycling has a three-method fallback chain — SAMR enumerate first, SAMR lookups second, LSARPC lookups third.

## Install

```bash
pip install -r requirements.txt
```

On Kali, impacket is already there. You probably just need:

```bash
pip install dnspython
```

## Usage

```bash
# Discover DCs via DNS, test for null/anonymous sessions
python3 nullsweep.py example.com

# Point at specific DCs
python3 nullsweep.py example.com --dc dc01.example.com
python3 nullsweep.py example.com --dc-file dcs.txt

# RID cycle to pull accounts
python3 nullsweep.py example.com --rid-cycle

# Full dump — users, machines, groups, shares, password policy, trusts
python3 nullsweep.py example.com --dump -o ./loot

# Clean userlist for spraying (one name per line, no machine accounts or junk)
python3 nullsweep.py example.com --rid-cycle --users-only > users.txt

# With creds instead of null sessions
python3 nullsweep.py example.com --dump -u jsmith -p 'Password1' -o ./loot

# Big domain? Bump the RID ceiling
python3 nullsweep.py example.com --dump --max-rid 200000 -o ./loot

# Full verbose output to stdout
python3 nullsweep.py example.com --dump -v
```

## Output Files

With `-o <dir>`:

* `users.txt` — user accounts, one per line, ready for spraying
* `computers.txt` — machine accounts (the `$` names)
* `service_accounts.txt` — MSA/gMSA accounts (GUID-looking names)
* `groups.txt` — domain groups
* `other.txt` — everything else that didn't fit the above categories
* `shares.txt` — shares with types and comments
* `policy.txt` — password and lockout policy

By default only summaries go to stdout. Use `-v` if you want the full listing printed.

## RID Cycling

Three methods, tried in order:

1. **SAMR EnumerateUsersInDomain** — asks the DC for all users. Fast and complete when it works, but null sessions often only get normal user accounts back (no machines).
2. **SAMR LookupIdsInDomain** — RID cycling through the SAMR pipe. Lookup-based, so it returns machine accounts, service accounts, everything.
3. **LSARPC LookupSids** — same idea, different pipe. Fallback when SAMR is locked down.

In `--dump` mode, method 1 runs first for speed, then RID cycling always runs on top to catch machine accounts and anything SAMR enumerate missed. Results get merged and deduplicated.

Default max RID is 100,000. Early stop kicks in after 20,000 consecutive empty RIDs.

## Flags

```
positional:
  domain                 Target AD domain

target selection:
  --dc HOST              Specific DC (repeatable)
  --dc-file FILE         DCs from a file, one per line
  --dns-server IP        DNS server for DC discovery

enumeration:
  --rid-cycle            RID cycle for accounts
  --dump                 Full enumeration dump
  --max-rid N            Max RID to cycle to (default 100000)
  --batch-size N         RIDs per batch (default/max 1000)

auth:
  -u, --username         Username (defaults to null/anon/guest testing)
  -p, --password         Password
  --hashes LM:NT         Pass the hash

output:
  -o, --output DIR       Write output files to this directory
  --users-only           Just usernames to stdout
  -v, --verbose          Full listings to stdout
  --no-color             Disable colors

other:
  --timeout SEC          Connection timeout (default 10)
  --debug                Debug logging
```

## Requirements

* Python 3.8+
* impacket >= 0.11.0
* dnspython >= 2.4.0
