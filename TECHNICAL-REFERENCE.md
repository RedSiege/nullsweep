# nullsweep — Technical Reference

## Overview

Single-file Python tool for comprehensive null/anonymous session enumeration
against Active Directory domain controllers. Pure impacket — no Samba client
dependencies.

## Dependencies

- `impacket` >= 0.11.0 — DCERPC/SMB protocol implementation
- `dnspython` >= 2.4.0 — DNS SRV record lookups for DC discovery

## Architecture

### Session Testing Matrix

Three auth methods tested in order against three RPC pipes:

| Method | Username | Password | Purpose |
|--------|----------|----------|---------|
| null | `''` | `''` | True null session |
| anonymous | `'anonymous'` | `''` | Explicit anonymous logon |
| guest | `<random 8-char>` | `''` | Guest account fallback |

Pipes tested per working session:
- `\samr` (SAMR — `MSRPC_UUID_SAMR`) — user/group enumeration, password policy
- `\lsarpc` (LSAT — `MSRPC_UUID_LSAT`) — SID lookups, domain info, trusts
- `\srvsvc` (SRVS — `MSRPC_UUID_SRVS`) — share enumeration

Each pipe is tested independently per auth method. The best (most anonymous)
working auth for each pipe is tracked and used for enumeration.

### RID Cycling Fallback Chain

Three methods tried in order:

1. **SAMR EnumerateUsersInDomain** (`hSamrEnumerateUsersInDomain`)
   - Complete enumeration, no guessing, paginated with enumerationContext
   - Null sessions typically only return normal user accounts (not machines)
   - Tries UAC filters: all (0), normal users (0x10), workstations (0x1000), DCs (0x2000)

2. **SAMR LookupIdsInDomain** (`hSamrLookupIdsInDomain`)
   - RID cycling through the SAMR pipe, batched 1000 per call
   - Lookup-based: returns any principal matching the RID, including machine accounts
   - Handles STATUS_SOME_NOT_MAPPED for partial batches

3. **LSARPC LookupSids** (`hLsarLookupSids`)
   - RID cycling through the LSARPC pipe
   - Constructs `{domain_sid}-{rid}` strings, batched 1000 per call
   - Fallback when SAMR pipe is completely blocked

In `--dump` mode, SAMR enumerate runs first (fast, gets user accounts), then
RID cycling always runs to catch machine accounts and anything SAMR missed.
Results are merged and deduplicated by RID.

### Account Categorization

Entries are categorized by name pattern, not SID type (since null sessions
often return Unknown type for valid objects):

| Category | Detection | Output File |
|----------|-----------|-------------|
| Users | No `$` suffix, not GUID, SidTypeUser | `users.txt` |
| Computers | Name ends in `$` | `computers.txt` |
| Service Accounts | 20+ hex-char name (MSA/gMSA GUIDs) | `service_accounts.txt` |
| Groups | SidTypeGroup / SidTypeAlias / SidTypeWellKnownGroup | `groups.txt` |
| Other | Everything else | `other.txt` |

### Early Stop Behavior

RID cycling stops after 20 consecutive empty batches (20,000 consecutive
unresolved RIDs) once past RID 1100. This prevents cycling through massive
empty ranges while still covering gaps between populated ranges. Override
with `--max-rid` for very large or sparse domains.

## Enumeration Capabilities

### Via SAMR (`\samr`)
- `hSamrEnumerateUsersInDomain` — user accounts (with UAC filter variants)
- `hSamrEnumerateGroupsInDomain` — domain groups
- `hSamrEnumerateAliasesInDomain` — aliases (local groups)
- `hSamrQueryInformationDomain` (DomainGeneralInformation) — account counts
- `hSamrQueryInformationDomain` (DomainPasswordInformation) — password policy
- `hSamrQueryInformationDomain` (DomainLockoutInformation) — lockout policy
- `hSamrLookupIdsInDomain` — RID-to-name resolution (RID cycling)

### Via LSARPC (`\lsarpc`)
- `hLsarQueryInformationPolicy2` (PolicyAccountDomainInformation) — domain SID
- `hLsarQueryInformationPolicy2` (PolicyDnsDomainInformation) — DNS domain, forest
- `hLsarEnumerateTrustedDomainsEx` — domain trusts
- `hLsarLookupSids` — SID-to-name resolution (RID cycling fallback)

### Via SRVSVC (`\srvsvc`)
- `hNetrShareEnum` — share listing with types and comments

### From SMB Session (no pipe needed)
- OS version and build
- NetBIOS name, domain, DNS domain
- SMB dialect (2.x/3.x)
- Signing requirement

## Impacket Compatibility

Handles differences across impacket versions:
- `SID_NAME_USE` members: works with both enum (`.value`) and plain int
- Name fields: coerces both `bytes` and `str` returns via `_str()` helper
- `LARGE_INTEGER` fields: handles both raw int and `OLD_LARGE_INTEGER` struct

## CLI Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `domain` | (required) | Target AD domain (positional) |
| `--dc HOST` | | Target specific DC (repeatable) |
| `--dc-file FILE` | | Read DCs from file |
| `--dns-server IP` | | Custom DNS server |
| `--rid-cycle` | | RID cycle for accounts |
| `--dump` | | Full enumeration |
| `--max-rid N` | 100000 | Max RID (minimum 100000) |
| `--batch-size N` | 1000 | Batch size (max 1000) |
| `-u` / `-p` | | Username / password |
| `--hashes LM:NT` | | Pass the hash |
| `-o DIR` | | Output directory |
| `--users-only` | | Just usernames to stdout |
| `-v` / `--verbose` | | Full listings to stdout |
| `--no-color` | | Disable ANSI colors |
| `--timeout SEC` | 10 | Connection timeout |
| `--debug` | | Debug logging |

## Output Files (with `-o`)

- `users.txt` — user accounts, one per line (spray-ready)
- `computers.txt` — machine accounts (with `$`)
- `service_accounts.txt` — MSA/gMSA GUID accounts
- `groups.txt` — domain groups
- `other.txt` — uncategorized entries
- `shares.txt` — share name, type, comment (tab-separated)
- `policy.txt` — password and lockout policy

## DNS Discovery

Queries in order:
1. `_ldap._tcp.dc._msdcs.<domain>` (SRV)
2. `_ldap._tcp.<domain>` (SRV)
3. `<domain>` (A record fallback)
