#!/usr/bin/env python3
"""
nullsweep - Comprehensive null/anonymous session scanner for AD domain controllers.

Discovers DCs via DNS, tests null/anonymous/guest session access across SAMR,
LSARPC, and SRVSVC pipes, and enumerates users, groups, shares, password
policies, and domain trusts through every available method with automatic
fallback.
"""

__version__ = "1.0.0"

import argparse
import re
import sys
import os
import socket
import logging
import random
import string
from datetime import timedelta
from collections import OrderedDict

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] dnspython required: pip install dnspython", file=sys.stderr)
    sys.exit(1)

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr, lsat, lsad, srvs
    from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.dcerpc.v5.samr import SID_NAME_USE
except ImportError:
    print("[!] impacket required: pip install impacket", file=sys.stderr)
    sys.exit(1)

log = logging.getLogger("nullsweep")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SID_TYPE_MAP = {
    0: "Unknown",
    1: "User",
    2: "Group",
    3: "Domain",
    4: "Alias",
    5: "WellKnownGroup",
    6: "DeletedAccount",
    7: "Invalid",
    8: "Unknown",
    9: "Computer",
    10: "Label",
}

PASSWORD_PROPS = {
    0x01: "Complexity required",
    0x02: "No anonymous change",
    0x04: "No clear-text change",
    0x08: "Lockout admins",
    0x10: "Store cleartext",
    0x20: "Refuse password change",
}

SMB_DIALECTS = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

WELL_KNOWN_RIDS = list(range(500, 526)) + [553, 498]


def _str(val):
    """Coerce impacket name fields (may be bytes, str, or RPC_UNICODE_STRING) to str."""
    if isinstance(val, bytes):
        return val.decode("utf-8", errors="replace")
    return str(val) if val else ""

def _sid_val(x):
    """Get the int value from a SID_NAME_USE member (works with both enum and int)."""
    return x.value if hasattr(x, "value") else int(x)

SID_USER = _sid_val(SID_NAME_USE.SidTypeUser)
SID_GROUP = _sid_val(SID_NAME_USE.SidTypeGroup)
SID_ALIAS = _sid_val(SID_NAME_USE.SidTypeAlias)
SID_WELLKNOWN = _sid_val(SID_NAME_USE.SidTypeWellKnownGroup)
SID_UNKNOWN = _sid_val(SID_NAME_USE.SidTypeUnknown)

STATUS_MORE_ENTRIES = 0x105
STATUS_SOME_NOT_MAPPED = 0x107
STATUS_NONE_MAPPED = 0xC0000073

_GUID_NAME_RE = re.compile(r"^[0-9A-Fa-f]{20,}$")


def _is_service_account_guid(name):
    """Detect MSA/gMSA accounts with GUID-style sAMAccountNames."""
    return bool(_GUID_NAME_RE.match(name))


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

class C:
    """ANSI color codes, disabled when stdout is not a terminal."""
    _enabled = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    @classmethod
    def disable(cls):
        cls._enabled = False

    @classmethod
    def _w(cls, code, text):
        return f"\033[{code}m{text}\033[0m" if cls._enabled else text

    @classmethod
    def green(cls, t):
        return cls._w("32", t)

    @classmethod
    def red(cls, t):
        return cls._w("31", t)

    @classmethod
    def yellow(cls, t):
        return cls._w("33", t)

    @classmethod
    def cyan(cls, t):
        return cls._w("36", t)

    @classmethod
    def bold(cls, t):
        return cls._w("1", t)

    @classmethod
    def dim(cls, t):
        return cls._w("2", t)


def info(msg):
    print(f"[{C.cyan('*')}] {msg}")

def good(msg):
    print(f"[{C.green('+')}] {msg}")

def bad(msg):
    print(f"[{C.red('-')}] {msg}")

def warn(msg):
    print(f"[{C.yellow('!')}] {msg}")

def indent(msg, level=1):
    print(f"{'    ' * level}{msg}")

def banner():
    print(C.bold(f"\n  nullsweep v{__version__}"))
    print(C.dim("  Comprehensive null/anonymous session scanner for AD\n"))


# ---------------------------------------------------------------------------
# DNS discovery
# ---------------------------------------------------------------------------

def discover_dcs(domain, nameserver=None):
    """Find domain controllers via DNS SRV records."""
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    resolver.lifetime = 10

    queries = [
        f"_ldap._tcp.dc._msdcs.{domain}",
        f"_ldap._tcp.{domain}",
    ]

    for query in queries:
        try:
            answers = resolver.resolve(query, "SRV")
            dcs = []
            for rdata in answers:
                hostname = str(rdata.target).rstrip(".")
                if hostname:
                    dcs.append(hostname)
            if dcs:
                return sorted(set(dcs))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue

    try:
        answers = resolver.resolve(domain, "A")
        return [str(rdata.address) for rdata in answers]
    except dns.exception.DNSException:
        return []


def resolve_host(hostname):
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

def smb_connect(target, username, password, domain="", timeout=10, port=445):
    """Create and authenticate an SMB connection. Returns (conn, info) or (None, error)."""
    try:
        smb = SMBConnection(target, target, sess_port=port, timeout=timeout)
        smb.login(username, password, domain)

        host_info = {
            "os": smb.getServerOS() or "",
            "domain": smb.getServerDomain() or "",
            "name": smb.getServerName() or "",
            "dns_domain": smb.getServerDNSDomainName() or "",
            "dns_host": smb.getServerDNSHostName() or "",
            "signing": smb.isSigningRequired(),
            "dialect": smb.getDialect(),
        }
        return smb, host_info

    except Exception as e:
        error = str(e)
        if port == 445:
            try:
                smb = SMBConnection(target, target, sess_port=139, timeout=timeout)
                smb.login(username, password, domain)
                host_info = {
                    "os": smb.getServerOS() or "",
                    "domain": smb.getServerDomain() or "",
                    "name": smb.getServerName() or "",
                    "dns_domain": smb.getServerDNSDomainName() or "",
                    "dns_host": smb.getServerDNSHostName() or "",
                    "signing": smb.isSigningRequired(),
                    "dialect": smb.getDialect(),
                }
                return smb, host_info
            except Exception:
                pass
        return None, error


def dce_connect(smb, pipe_name, uuid):
    """Bind a DCERPC connection to a named pipe over an existing SMB session."""
    try:
        rpctransport = transport.SMBTransport(
            smb.getRemoteHost(),
            filename=pipe_name,
            smb_connection=smb,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(uuid)
        return dce
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Session and pipe testing
# ---------------------------------------------------------------------------

def generate_guest_name():
    return "".join(random.choices(string.ascii_lowercase, k=8))


def test_dc_access(target, domain, timeout=10, creds=None):
    """
    Test a DC for session and pipe access.

    Returns a dict with:
        host_info: SMB host metadata
        sessions: {method: bool}
        pipes: {method: {pipe: bool}}
        best: {pipe: method}  (best auth for each pipe)
        smb_conns: {method: SMBConnection}  (live connections for working methods)
    """
    result = {
        "host_info": {},
        "sessions": OrderedDict(),
        "pipes": OrderedDict(),
        "best": {},
        "smb_conns": {},
    }

    if creds:
        methods = [("creds", creds[0], creds[1])]
    else:
        methods = [
            ("null", "", ""),
            ("anonymous", "anonymous", ""),
            ("guest", generate_guest_name(), ""),
        ]

    for method_name, username, password in methods:
        smb, info_or_err = smb_connect(target, username, password, domain, timeout)

        if smb is None:
            result["sessions"][method_name] = False
            result["pipes"][method_name] = {}
            continue

        result["sessions"][method_name] = True

        if not result["host_info"]:
            result["host_info"] = info_or_err

        pipe_access = {}
        for pipe_label, pipe_path, pipe_uuid in [
            ("samr", r"\samr", samr.MSRPC_UUID_SAMR),
            ("lsarpc", r"\lsarpc", lsat.MSRPC_UUID_LSAT),
            ("srvsvc", r"\srvsvc", srvs.MSRPC_UUID_SRVS),
        ]:
            dce = dce_connect(smb, pipe_path, pipe_uuid)
            if dce:
                pipe_access[pipe_label] = True
                try:
                    dce.disconnect()
                except Exception:
                    pass
            else:
                pipe_access[pipe_label] = False

        result["pipes"][method_name] = pipe_access
        result["smb_conns"][method_name] = smb

    for pipe_label in ["samr", "lsarpc", "srvsvc"]:
        for method_name in result["pipes"]:
            if result["pipes"][method_name].get(pipe_label):
                result["best"][pipe_label] = method_name
                break

    return result


# ---------------------------------------------------------------------------
# SAMR enumeration
# ---------------------------------------------------------------------------

def samr_setup(smb, target):
    """Open SAMR and return (dce, server_handle, domain_handle, domain_sid_str, domain_name)."""
    dce = dce_connect(smb, r"\samr", samr.MSRPC_UUID_SAMR)
    if not dce:
        return None

    try:
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp["Buffer"]["Buffer"]

        domain_name = None
        for d in domains:
            name = d["Name"]
            if name.upper() != "BUILTIN":
                domain_name = name
                break

        if not domain_name and domains:
            domain_name = domains[0]["Name"]

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]
        domain_sid_str = domain_sid.formatCanonical()

        resp = samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
        domain_handle = resp["DomainHandle"]

        return dce, server_handle, domain_handle, domain_sid_str, domain_name

    except Exception as e:
        log.debug(f"SAMR setup failed: {e}")
        try:
            dce.disconnect()
        except Exception:
            pass
        return None


USER_NORMAL_ACCOUNT = 0x00000010
USER_WORKSTATION_TRUST_ACCOUNT = 0x00001000
USER_SERVER_TRUST_ACCOUNT = 0x00002000


def _samr_enumerate_with_filter(dce, domain_handle, uac_filter=0):
    """Enumerate accounts via hSamrEnumerateUsersInDomain with a UAC filter."""
    entries = []
    enum_context = 0

    while True:
        try:
            resp = samr.hSamrEnumerateUsersInDomain(
                dce, domain_handle, enum_context, uac_filter,
            )
        except DCERPCException as e:
            if "STATUS_MORE_ENTRIES" in str(e):
                resp = e.get_packet()
            else:
                raise

        for entry in resp["Buffer"]["Buffer"]:
            name = _str(entry["Name"])
            entries.append({
                "name": name,
                "rid": entry["RelativeId"],
                "type": "Computer" if name.endswith("$") else "User",
                "type_id": SID_USER,
            })

        enum_context = resp["EnumerationContext"]
        status = resp["ErrorCode"]
        if status != STATUS_MORE_ENTRIES:
            break

    return entries


def samr_enumerate_users(dce, domain_handle):
    """Enumerate all accounts: users first, then machine accounts, then DCs."""
    seen_rids = set()
    all_entries = []

    for label, uac_filter in [
        ("all accounts (no filter)", 0),
        ("normal users", USER_NORMAL_ACCOUNT),
        ("workstations", USER_WORKSTATION_TRUST_ACCOUNT),
        ("domain controllers", USER_SERVER_TRUST_ACCOUNT),
    ]:
        try:
            entries = _samr_enumerate_with_filter(dce, domain_handle, uac_filter)
            new = 0
            for e in entries:
                if e["rid"] not in seen_rids:
                    seen_rids.add(e["rid"])
                    all_entries.append(e)
                    new += 1
            if new:
                log.debug(f"SAMR enumerate ({label}): {new} new entries")
        except Exception as e:
            log.debug(f"SAMR enumerate ({label}) failed: {e}")

        if uac_filter == 0 and all_entries:
            break

    return all_entries


def samr_enumerate_groups(dce, domain_handle):
    """Enumerate domain groups via SAMR."""
    groups = []
    enum_context = 0

    while True:
        try:
            resp = samr.hSamrEnumerateGroupsInDomain(dce, domain_handle, enum_context)
        except DCERPCException as e:
            if "STATUS_MORE_ENTRIES" in str(e):
                resp = e.get_packet()
            else:
                raise

        for entry in resp["Buffer"]["Buffer"]:
            groups.append({
                "name": _str(entry["Name"]),
                "rid": entry["RelativeId"],
                "type": "Group",
            })

        enum_context = resp["EnumerationContext"]
        status = resp["ErrorCode"]
        if status != STATUS_MORE_ENTRIES:
            break

    return groups


def samr_enumerate_aliases(dce, domain_handle):
    """Enumerate aliases (local groups) via SAMR."""
    aliases = []
    enum_context = 0

    while True:
        try:
            resp = samr.hSamrEnumerateAliasesInDomain(dce, domain_handle, enum_context)
        except DCERPCException as e:
            if "STATUS_MORE_ENTRIES" in str(e):
                resp = e.get_packet()
            else:
                raise

        for entry in resp["Buffer"]["Buffer"]:
            aliases.append({
                "name": _str(entry["Name"]),
                "rid": entry["RelativeId"],
                "type": "Alias",
            })

        enum_context = resp["EnumerationContext"]
        status = resp["ErrorCode"]
        if status != STATUS_MORE_ENTRIES:
            break

    return aliases


def samr_domain_stats(dce, domain_handle):
    """Query domain general info for total account counts."""
    try:
        resp = samr.hSamrQueryInformationDomain(
            dce, domain_handle,
            samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation,
        )
        general = resp["Buffer"]["General"]
        return {
            "total_users": general["UserCount"],
            "total_groups": general["GroupCount"],
            "total_aliases": general["AliasCount"],
        }
    except Exception as e:
        log.debug(f"Domain stats query failed: {e}")
        return None


def samr_password_policy(dce, domain_handle):
    """Query password and lockout policy via SAMR."""
    policy = {}

    try:
        resp = samr.hSamrQueryInformationDomain(
            dce, domain_handle,
            samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
        )
        pwd_info = resp["Buffer"]["Password"]
        policy["min_length"] = pwd_info["MinPasswordLength"]
        policy["history"] = pwd_info["PasswordHistoryLength"]
        policy["properties"] = pwd_info["PasswordProperties"]

        max_age_raw = _large_int(pwd_info["MaxPasswordAge"])
        min_age_raw = _large_int(pwd_info["MinPasswordAge"])
        policy["max_age"] = _filetime_to_str(max_age_raw)
        policy["min_age"] = _filetime_to_str(min_age_raw)

        props = pwd_info["PasswordProperties"]
        policy["complexity"] = bool(props & 0x01)
        policy["cleartext_storage"] = bool(props & 0x10)

        flags = []
        for bit, label in PASSWORD_PROPS.items():
            if props & bit:
                flags.append(label)
        policy["property_flags"] = flags

    except Exception as e:
        log.debug(f"Password policy query failed: {e}")

    try:
        resp = samr.hSamrQueryInformationDomain(
            dce, domain_handle,
            samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
        )
        lockout = resp["Buffer"]["Lockout"]
        policy["lockout_threshold"] = lockout["LockoutThreshold"]

        duration_raw = _large_int(lockout["LockoutDuration"])
        window_raw = _large_int(lockout["LockoutObservationWindow"])
        policy["lockout_duration"] = _filetime_to_str(duration_raw)
        policy["lockout_window"] = _filetime_to_str(window_raw)

    except Exception as e:
        log.debug(f"Lockout policy query failed: {e}")

    return policy


def samr_lookup_ids(dce, domain_handle, rids):
    """
    Resolve a batch of RIDs to names via SAMR hSamrLookupIdsInDomain.
    Returns list of {rid, name, type_id, type}.
    """
    results = []
    try:
        resp = samr.hSamrLookupIdsInDomain(dce, domain_handle, rids)
    except DCERPCException as e:
        err = str(e)
        if "STATUS_NONE_MAPPED" in err:
            return results
        if "STATUS_SOME_NOT_MAPPED" in err:
            resp = e.get_packet()
        else:
            raise

    names = resp["Names"]["Element"]
    uses = resp["Use"]["Element"]

    for i in range(len(names)):
        name_val = _str(names[i]["Data"])
        use_val = uses[i]
        if use_val != SID_UNKNOWN:
            results.append({
                "rid": rids[i],
                "name": name_val,
                "type_id": use_val,
                "type": SID_TYPE_MAP.get(use_val, "Unknown"),
            })

    return results


def _large_int(li):
    """Convert OLD_LARGE_INTEGER struct or raw LARGE_INTEGER int to signed 64-bit."""
    if isinstance(li, int):
        val = li
    else:
        low = li["LowPart"] & 0xFFFFFFFF
        high = li["HighPart"] & 0xFFFFFFFF
        val = (high << 32) | low
    if val >= (1 << 63):
        val -= 1 << 64
    return val


def _filetime_to_str(ft):
    """Convert a FILETIME interval (negative 100ns ticks) to human-readable."""
    if ft == 0 or abs(ft) >= 0x7FFFFFFFFFFFFFFF:
        return "Never / Not set"
    seconds = abs(ft) / 10_000_000
    if seconds < 60:
        return f"{int(seconds)} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    return f"{int(days)} days"


# ---------------------------------------------------------------------------
# LSARPC enumeration
# ---------------------------------------------------------------------------

def lsa_get_domain_info(smb, target):
    """Query domain info and trusts via LSARPC."""
    dce = dce_connect(smb, r"\lsarpc", lsad.MSRPC_UUID_LSAD)
    if not dce:
        return None

    result = {"domain_sid": None, "dns_domain": None, "forest": None, "trusts": []}

    try:
        resp = lsad.hLsarOpenPolicy2(
            dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES,
        )
        policy_handle = resp["PolicyHandle"]

        try:
            resp = lsad.hLsarQueryInformationPolicy2(
                dce, policy_handle,
                lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation,
            )
            acct_info = resp["PolicyInformation"]["PolicyAccountDomainInfo"]
            result["domain_sid"] = acct_info["DomainSid"].formatCanonical()
        except Exception as e:
            log.debug(f"LSA PolicyAccountDomainInfo failed: {e}")

        try:
            resp = lsad.hLsarQueryInformationPolicy2(
                dce, policy_handle,
                lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation,
            )
            dns_info = resp["PolicyInformation"]["PolicyDnsDomainInfo"]
            result["dns_domain"] = _str(dns_info["DnsDomainName"]["Buffer"])
            result["forest"] = _str(dns_info["DnsForestName"]["Buffer"])
        except Exception as e:
            log.debug(f"LSA PolicyDnsDomainInfo failed: {e}")

        try:
            resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policy_handle)
            for entry in resp["EnumerationBuffer"]["EnumerationBuffer"]:
                trust = {
                    "name": _str(entry["Name"]["Buffer"]),
                    "flat_name": _str(entry["FlatName"]["Buffer"]),
                    "sid": entry["Sid"].formatCanonical() if entry["Sid"] else "",
                    "direction": entry["TrustDirection"],
                    "type": entry["TrustType"],
                    "attributes": entry["TrustAttributes"],
                }
                result["trusts"].append(trust)
        except Exception as e:
            log.debug(f"LSA trust enumeration failed: {e}")

    except Exception as e:
        log.debug(f"LSA policy open failed: {e}")
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass

    return result


def lsa_lookup_sids(smb, target, domain_sid_str, rids):
    """
    Resolve RIDs to names via LSARPC hLsarLookupSids.
    Returns list of {rid, name, domain, type_id, type}.
    """
    dce = dce_connect(smb, r"\lsarpc", lsat.MSRPC_UUID_LSAT)
    if not dce:
        return None

    results = []
    try:
        resp = lsad.hLsarOpenPolicy2(
            dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES,
        )
        policy_handle = resp["PolicyHandle"]

        sids = [f"{domain_sid_str}-{rid}" for rid in rids]

        try:
            resp = lsat.hLsarLookupSids(
                dce, policy_handle, sids,
                lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta,
            )
        except DCERPCException as e:
            err = str(e)
            if "STATUS_NONE_MAPPED" in err:
                return results
            if "STATUS_SOME_NOT_MAPPED" in err:
                resp = e.get_packet()
            else:
                raise

        domain_list = resp["ReferencedDomains"]["Domains"]
        names = resp["TranslatedNames"]["Names"]

        for i, entry in enumerate(names):
            use_val = entry["Use"]
            if use_val != SID_UNKNOWN:
                domain_idx = entry["DomainIndex"]
                domain_name = ""
                if 0 <= domain_idx < len(domain_list):
                    domain_name = _str(domain_list[domain_idx]["Name"])

                results.append({
                    "rid": rids[i],
                    "name": _str(entry["Name"]),
                    "domain": domain_name,
                    "type_id": use_val,
                    "type": SID_TYPE_MAP.get(use_val, "Unknown"),
                })

    except Exception as e:
        log.debug(f"LSA SID lookup failed: {e}")
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass

    return results


# ---------------------------------------------------------------------------
# SRVSVC enumeration
# ---------------------------------------------------------------------------

def enum_shares(smb, target):
    """Enumerate shares via SRVSVC."""
    dce = dce_connect(smb, r"\srvsvc", srvs.MSRPC_UUID_SRVS)
    if not dce:
        return None

    shares = []
    try:
        resp = srvs.hNetrShareEnum(dce, 1)
        for entry in resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]:
            share_type = entry["shi1_type"]
            type_name = "Unknown"
            base_type = share_type & 0x0FFFFFFF
            if base_type == 0:
                type_name = "Disk"
            elif base_type == 1:
                type_name = "Printer"
            elif base_type == 2:
                type_name = "Device"
            elif base_type == 3:
                type_name = "IPC"

            shares.append({
                "name": entry["shi1_netname"][:-1],
                "type": type_name,
                "comment": entry["shi1_remark"][:-1],
            })
    except Exception as e:
        log.debug(f"Share enumeration failed: {e}")
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass

    return shares


# ---------------------------------------------------------------------------
# RID cycling - multi-method with automatic fallback
# ---------------------------------------------------------------------------

def rid_cycle(access_result, target, domain, max_rid=10000, batch_size=1000,
              skip_enumerate=False):
    """
    Enumerate accounts via RID cycling with three-level fallback:
        1. SAMR EnumerateUsersInDomain (complete, no guessing) — skipped if skip_enumerate
        2. SAMR LookupIdsInDomain (RID cycling via SAMR pipe)
        3. LSARPC LookupSids (RID cycling via LSA pipe)

    Returns (entries, method_used, domain_sid_str).
    """
    samr_method = access_result["best"].get("samr")
    lsa_method = access_result["best"].get("lsarpc")

    # --- Method 1: SAMR full enumeration (skipped in --dump, already done) ---
    if samr_method and not skip_enumerate:
        smb = access_result["smb_conns"][samr_method]
        setup = samr_setup(smb, target)
        if setup:
            dce, server_handle, domain_handle, domain_sid_str, domain_name = setup
            info("Trying SAMR EnumerateUsersInDomain (complete enumeration)...")
            try:
                users = samr_enumerate_users(dce, domain_handle)
                if users:
                    good(f"SAMR EnumerateUsers returned {len(users)} users")
                    try:
                        dce.disconnect()
                    except Exception:
                        pass
                    return users, "SAMR EnumerateUsersInDomain", domain_sid_str
            except Exception as e:
                warn(f"SAMR EnumerateUsers denied: {e}")

            # --- Method 2: SAMR RID cycling ---
            info("Trying SAMR LookupIdsInDomain (RID cycling via SAMR)...")
            entries = _rid_cycle_samr(dce, domain_handle, max_rid, batch_size)
            try:
                dce.disconnect()
            except Exception:
                pass
            if entries:
                good(f"SAMR RID cycling found {len(entries)} entries")
                return entries, "SAMR LookupIdsInDomain", domain_sid_str

    # --- Method 2 (when skipping enumerate): SAMR RID cycling directly ---
    if samr_method and skip_enumerate:
        smb = access_result["smb_conns"][samr_method]
        setup = samr_setup(smb, target)
        if setup:
            dce, server_handle, domain_handle, domain_sid_str, domain_name = setup
            info("SAMR RID cycling (LookupIdsInDomain)...")
            entries = _rid_cycle_samr(dce, domain_handle, max_rid, batch_size)
            try:
                dce.disconnect()
            except Exception:
                pass
            if entries:
                good(f"SAMR RID cycling found {len(entries)} entries")
                return entries, "SAMR LookupIdsInDomain", domain_sid_str

    # --- Method 3: LSARPC RID cycling ---
    if lsa_method:
        smb = access_result["smb_conns"][lsa_method]
        info("Trying LSARPC LookupSids (RID cycling via LSA)...")

        domain_sid_str = _get_domain_sid(smb, target, access_result)
        if not domain_sid_str:
            bad("Cannot determine domain SID — RID cycling impossible")
            return [], "none", None

        entries = _rid_cycle_lsa(smb, target, domain_sid_str, max_rid, batch_size)
        if entries:
            good(f"LSARPC RID cycling found {len(entries)} entries")
            return entries, "LSARPC LookupSids", domain_sid_str

    bad("All RID cycling methods failed — no accessible pipe")
    return [], "none", None


def _get_domain_sid(smb, target, access_result):
    """Get the domain SID from LSARPC or SAMR."""
    lsa_method = access_result["best"].get("lsarpc")
    if lsa_method:
        lsa_smb = access_result["smb_conns"][lsa_method]
        lsa_info = lsa_get_domain_info(lsa_smb, target)
        if lsa_info and lsa_info["domain_sid"]:
            return lsa_info["domain_sid"]

    samr_method = access_result["best"].get("samr")
    if samr_method:
        samr_smb = access_result["smb_conns"][samr_method]
        setup = samr_setup(samr_smb, target)
        if setup:
            dce, _, _, sid_str, _ = setup
            try:
                dce.disconnect()
            except Exception:
                pass
            return sid_str

    return None


def _rid_cycle_samr(dce, domain_handle, max_rid, batch_size):
    """RID cycle using SAMR LookupIdsInDomain."""
    all_entries = []
    total_batches = (max_rid + batch_size - 1) // batch_size
    consecutive_empty = 0
    stop_threshold = 20

    for batch_num in range(total_batches):
        start = batch_num * batch_size
        end = min(start + batch_size, max_rid)
        rids = list(range(start, end))

        try:
            entries = samr_lookup_ids(dce, domain_handle, rids)
            if entries:
                all_entries.extend(entries)
                consecutive_empty = 0
                if not log.isEnabledFor(logging.DEBUG):
                    _print_progress(start, max_rid)
            else:
                consecutive_empty += 1
        except DCERPCException as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                warn("SAMR LookupIds denied — falling back")
                return []
            consecutive_empty += 1

        if start >= 1100 and consecutive_empty >= stop_threshold:
            break

    _clear_progress()
    return all_entries


def _rid_cycle_lsa(smb, target, domain_sid_str, max_rid, batch_size):
    """RID cycle using LSARPC LookupSids."""
    all_entries = []
    total_batches = (max_rid + batch_size - 1) // batch_size
    consecutive_empty = 0
    stop_threshold = 20

    for batch_num in range(total_batches):
        start = batch_num * batch_size
        end = min(start + batch_size, max_rid)
        rids = list(range(start, end))

        entries = lsa_lookup_sids(smb, target, domain_sid_str, rids)
        if entries is None:
            warn("LSARPC connection lost during RID cycling")
            break

        if entries:
            all_entries.extend(entries)
            consecutive_empty = 0
            if not log.isEnabledFor(logging.DEBUG):
                _print_progress(start, max_rid, len(all_entries))
        else:
            consecutive_empty += 1

        if start >= 1100 and consecutive_empty >= stop_threshold:
            break

    _clear_progress()
    return all_entries


def _print_progress(current, total):
    pct = min(100, int(current / total * 100))
    sys.stderr.write(f"\r    RID cycling: {pct}% ({current}/{total})")
    sys.stderr.flush()


def _clear_progress():
    sys.stderr.write("\r" + " " * 70 + "\r")
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Full dump orchestration
# ---------------------------------------------------------------------------

def full_dump(access_result, target, domain, max_rid=10000, batch_size=1000):
    """Run all enumeration operations and return structured results."""
    results = {
        "host_info": access_result["host_info"],
        "sessions": access_result["sessions"],
        "pipes": access_result["pipes"],
        "users": [],
        "groups": [],
        "aliases": [],
        "shares": [],
        "password_policy": {},
        "domain_info": {},
        "trusts": [],
        "rid_entries": [],
        "rid_method": "none",
    }

    # LSARPC: domain info and trusts
    lsa_method = access_result["best"].get("lsarpc")
    if lsa_method:
        info("Querying domain info via LSARPC...")
        smb = access_result["smb_conns"][lsa_method]
        lsa_info = lsa_get_domain_info(smb, target)
        if lsa_info:
            results["domain_info"] = lsa_info
            if lsa_info.get("domain_sid"):
                good(f"Domain SID: {lsa_info['domain_sid']}")
            if lsa_info.get("dns_domain"):
                good(f"DNS Domain: {lsa_info['dns_domain']}")
            if lsa_info.get("forest"):
                good(f"Forest: {lsa_info['forest']}")
            if lsa_info.get("trusts"):
                results["trusts"] = lsa_info["trusts"]
                good(f"Found {len(lsa_info['trusts'])} domain trust(s)")

    # SAMR: users, groups, password policy
    domain_stats = None
    samr_method = access_result["best"].get("samr")
    if samr_method:
        smb = access_result["smb_conns"][samr_method]
        setup = samr_setup(smb, target)
        if setup:
            dce, server_handle, domain_handle, domain_sid_str, domain_name = setup

            info("Querying domain account counts...")
            domain_stats = samr_domain_stats(dce, domain_handle)
            if domain_stats:
                total = (domain_stats["total_users"]
                         + domain_stats["total_groups"]
                         + domain_stats["total_aliases"])
                good(f"Domain reports: {domain_stats['total_users']} users, "
                     f"{domain_stats['total_groups']} groups, "
                     f"{domain_stats['total_aliases']} aliases "
                     f"({total} total objects)")
                results["domain_stats"] = domain_stats

            info("Enumerating users via SAMR...")
            try:
                users = samr_enumerate_users(dce, domain_handle)
                results["users"] = users
                good(f"Found {len(users)} users via SAMR EnumerateUsers")
            except Exception as e:
                warn(f"SAMR user enumeration failed: {e}")

            info("Enumerating groups via SAMR...")
            try:
                groups = samr_enumerate_groups(dce, domain_handle)
                results["groups"] = groups
                good(f"Found {len(groups)} domain groups")
            except Exception as e:
                warn(f"SAMR group enumeration failed: {e}")

            info("Enumerating aliases via SAMR...")
            try:
                aliases = samr_enumerate_aliases(dce, domain_handle)
                results["aliases"] = aliases
                good(f"Found {len(aliases)} aliases")
            except Exception as e:
                warn(f"SAMR alias enumeration failed: {e}")

            info("Querying password policy via SAMR...")
            try:
                policy = samr_password_policy(dce, domain_handle)
                results["password_policy"] = policy
                good("Retrieved password policy")
            except Exception as e:
                warn(f"Password policy query failed: {e}")

            try:
                dce.disconnect()
            except Exception:
                pass

    # SRVSVC: shares
    srvsvc_method = access_result["best"].get("srvsvc")
    if srvsvc_method:
        info("Enumerating shares via SRVSVC...")
        smb = access_result["smb_conns"][srvsvc_method]
        shares = enum_shares(smb, target)
        if shares:
            results["shares"] = shares
            good(f"Found {len(shares)} shares")

    effective_max_rid = max(max_rid, 100000)

    # RID cycling — always run to catch machine accounts and objects
    # that SAMR enumerate can't see via null session
    samr_rids = {u["rid"] for u in results["users"]}
    had_samr_users = bool(results["users"])

    if had_samr_users:
        info("RID cycling for machine accounts and service accounts...")
    else:
        info("SAMR user enumeration unavailable — RID cycling for all accounts...")

    entries, method, domain_sid_str = rid_cycle(
        access_result, target, domain, effective_max_rid, batch_size,
        skip_enumerate=had_samr_users,
    )

    # Merge: keep anything RID cycling found that SAMR enumerate missed
    new_entries = [e for e in entries if e["rid"] not in samr_rids]
    if new_entries:
        good(f"RID cycling found {len(new_entries)} accounts beyond SAMR enumerate")
    results["rid_entries"] = new_entries
    results["rid_method"] = method

    return results


# ---------------------------------------------------------------------------
# Output formatting and file writing
# ---------------------------------------------------------------------------

def print_access_results(target, ip, access):
    """Print the session and pipe testing results for a DC."""
    dialect = access["host_info"].get("dialect", 0)
    dialect_str = SMB_DIALECTS.get(dialect, "SMBv1" if dialect else "Unknown")
    signing = access["host_info"].get("signing", False)
    os_str = access["host_info"].get("os", "Unknown")
    name = access["host_info"].get("name", "")

    print()
    info(f"Target: {C.bold(target)} ({ip or '?'})")
    indent(f"OS: {os_str}  |  Name: {name}  |  SMB: {dialect_str}  |  Signing: {signing}")

    for method, success in access["sessions"].items():
        if success:
            indent(f"{C.green('+')} {method:10s} session: {C.green('ALLOWED')}")
        else:
            indent(f"{C.red('-')} {method:10s} session: {C.red('DENIED')}")

    for method, pipes in access["pipes"].items():
        if not access["sessions"].get(method):
            continue
        for pipe, accessible in pipes.items():
            if accessible:
                indent(f"    {C.green('+')} {pipe:8s} pipe via {method}: {C.green('ACCESSIBLE')}")
            else:
                indent(f"    {C.red('-')} {pipe:8s} pipe via {method}: {C.red('DENIED')}")

    if access["best"]:
        indent(C.dim("Best auth per pipe:"))
        for pipe, method in access["best"].items():
            indent(f"    {pipe}: {method}", 1)


def print_dump_results(results, target, verbose=False):
    """Print enumeration results. Summary by default, full listing with --verbose."""
    print(f"\n{'=' * 60}")
    print(C.bold(f"  ENUMERATION RESULTS — {target}"))
    print(f"{'=' * 60}")

    # Domain info
    di = results.get("domain_info", {})
    if di:
        print(f"\n{C.bold('--- Domain Info ---')}")
        if di.get("domain_sid"):
            print(f"  Domain SID:  {di['domain_sid']}")
        if di.get("dns_domain"):
            print(f"  DNS Domain:  {di['dns_domain']}")
        if di.get("forest"):
            print(f"  Forest:      {di['forest']}")

    # Domain stats
    ds = results.get("domain_stats", {})
    if ds:
        print(f"\n{C.bold('--- Domain Stats ---')}")
        print(f"  Users:    {ds.get('total_users', '?')}")
        print(f"  Groups:   {ds.get('total_groups', '?')}")
        print(f"  Aliases:  {ds.get('total_aliases', '?')}")

    # Trusts (always show — usually a small list)
    if results.get("trusts"):
        print(f"\n{C.bold('--- Domain Trusts ---')}")
        for t in results["trusts"]:
            direction = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
            dir_str = direction.get(t["direction"], str(t["direction"]))
            print(f"  {t['name']:<40s} {dir_str:<15s} SID: {t['sid']}")

    # Password policy (always show — critical intel)
    pp = results.get("password_policy", {})
    if pp:
        print(f"\n{C.bold('--- Password Policy ---')}")
        print(f"  Min length:         {pp.get('min_length', '?')}")
        print(f"  History:            {pp.get('history', '?')}")
        print(f"  Max age:            {pp.get('max_age', '?')}")
        print(f"  Min age:            {pp.get('min_age', '?')}")
        print(f"  Complexity:         {'Yes' if pp.get('complexity') else 'No'}")
        print(f"  Lockout threshold:  {pp.get('lockout_threshold', '?')}")
        print(f"  Lockout duration:   {pp.get('lockout_duration', '?')}")
        print(f"  Lockout window:     {pp.get('lockout_window', '?')}")
        if pp.get("cleartext_storage"):
            print(f"  {C.red('!! Cleartext password storage ENABLED !!')}")

    # Shares (always show — usually a short list)
    shares = results.get("shares", [])
    if shares:
        print(f"\n{C.bold(f'--- Shares ({len(shares)}) ---')}")
        for s in shares:
            print(f"  {s['name']:<20s} {s['type']:<10s} {s['comment']}")

    # Users and computers (from SAMR enumerate)
    all_samr = results.get("users", [])
    if all_samr:
        samr_users = [u for u in all_samr if not u["name"].endswith("$")]
        samr_computers = [u for u in all_samr if u["name"].endswith("$")]

        if samr_users:
            if verbose:
                print(f"\n{C.bold(f'--- Users ({len(samr_users)}) ---')}")
                for u in sorted(samr_users, key=lambda x: x["rid"]):
                    print(f"  {u['rid']:<8d} {u['name']}")
            else:
                print(f"\n  {C.bold('Users:')} {len(samr_users)} enumerated via SAMR")

        if samr_computers:
            if verbose:
                print(f"\n{C.bold(f'--- Computers ({len(samr_computers)}) ---')}")
                for u in sorted(samr_computers, key=lambda x: x["rid"]):
                    print(f"  {u['rid']:<8d} {u['name']}")
            else:
                print(f"  {C.bold('Computers:')} {len(samr_computers)} enumerated via SAMR")

    # RID cycle entries
    rid_entries = results.get("rid_entries", [])
    if rid_entries:
        method = results.get("rid_method", "RID cycling")
        users_r, computers_r, svcaccts_r, groups_r, other_r = categorize_entries(rid_entries)

        if verbose:
            for label, entries in [("Users", users_r), ("Computers", computers_r),
                                   ("Service Accounts", svcaccts_r),
                                   ("Groups", groups_r), ("Other", other_r)]:
                if entries:
                    print(f"\n{C.bold(f'--- {label} via {method} ({len(entries)}) ---')}")
                    for e in sorted(entries, key=lambda x: x["rid"]):
                        print(f"  {e['rid']:<8d} {e['name']}")
        else:
            parts = []
            if users_r:
                parts.append(f"{len(users_r)} users")
            if computers_r:
                parts.append(f"{len(computers_r)} computers")
            if svcaccts_r:
                parts.append(f"{len(svcaccts_r)} service accounts")
            if groups_r:
                parts.append(f"{len(groups_r)} groups")
            if other_r:
                parts.append(f"{len(other_r)} other")
            if parts:
                print(f"\n  {C.bold('RID cycling:')} {', '.join(parts)} via {method}")

    # Groups and aliases from SAMR
    groups = results.get("groups", [])
    aliases = results.get("aliases", [])
    if groups or aliases:
        if verbose:
            if groups:
                print(f"\n{C.bold(f'--- Domain Groups ({len(groups)}) ---')}")
                for g in sorted(groups, key=lambda x: x["rid"]):
                    print(f"  {g['rid']:<8d} {g['name']}")
            if aliases:
                print(f"\n{C.bold(f'--- Aliases ({len(aliases)}) ---')}")
                for a in sorted(aliases, key=lambda x: x["rid"]):
                    print(f"  {a['rid']:<8d} {a['name']}")
        else:
            if groups:
                print(f"  {C.bold('Domain Groups:')} {len(groups)}")
            if aliases:
                print(f"  {C.bold('Aliases:')} {len(aliases)}")

    if not verbose:
        print(f"\n  {C.dim('Full listings written to output files. Use --verbose to print to stdout.')}")

    print()


def categorize_entries(entries):
    """Split RID cycling entries into users, computers, service accounts, groups, and other."""
    users, computers, service_accounts, groups, other = [], [], [], [], []
    for e in entries:
        name = e.get("name", "")
        type_id = e.get("type_id", 0)
        if name.endswith("$"):
            computers.append(e)
        elif _is_service_account_guid(name):
            service_accounts.append(e)
        elif type_id == SID_USER:
            users.append(e)
        elif type_id in (SID_GROUP, SID_ALIAS, SID_WELLKNOWN):
            groups.append(e)
        else:
            other.append(e)
    return users, computers, service_accounts, groups, other


def write_output_files(results, output_dir, target):
    """Write enumeration results to files in the output directory."""
    os.makedirs(output_dir, exist_ok=True)

    # Categorize all entries properly
    all_users = []
    all_computers = []
    all_service_accounts = []

    for u in results.get("users", []):
        name = u["name"]
        if name.endswith("$"):
            all_computers.append(name)
        elif _is_service_account_guid(name):
            all_service_accounts.append(name)
        else:
            all_users.append(name)

    rid_entries = results.get("rid_entries", [])
    if rid_entries:
        r_users, r_computers, r_svcaccts, r_groups, r_other = categorize_entries(rid_entries)
        all_users.extend(e["name"] for e in r_users)
        all_computers.extend(e["name"] for e in r_computers)
        all_service_accounts.extend(e["name"] for e in r_svcaccts)

    if all_users:
        path = os.path.join(output_dir, "users.txt")
        with open(path, "w") as f:
            for name in sorted(set(all_users)):
                f.write(f"{name}\n")
        good(f"Wrote {len(set(all_users))} users to {path}")

    if all_computers:
        path = os.path.join(output_dir, "computers.txt")
        with open(path, "w") as f:
            for name in sorted(set(all_computers)):
                f.write(f"{name}\n")
        good(f"Wrote {len(set(all_computers))} computers to {path}")

    if all_service_accounts:
        path = os.path.join(output_dir, "service_accounts.txt")
        with open(path, "w") as f:
            for name in sorted(set(all_service_accounts)):
                f.write(f"{name}\n")
        good(f"Wrote {len(set(all_service_accounts))} service accounts to {path}")

    # "Other" from RID cycling (groups with Unknown type, misc objects)
    if rid_entries:
        _, _, _, _, r_other = categorize_entries(rid_entries)
        if r_other:
            path = os.path.join(output_dir, "other.txt")
            with open(path, "w") as f:
                for e in sorted(r_other, key=lambda x: x["name"]):
                    f.write(f"{e['name']}\n")
            good(f"Wrote {len(r_other)} uncategorized entries to {path}")

    groups = results.get("groups", [])
    if groups:
        path = os.path.join(output_dir, "groups.txt")
        with open(path, "w") as f:
            for g in sorted(groups, key=lambda x: x["name"]):
                f.write(f"{g['name']}\n")
        good(f"Wrote {len(groups)} groups to {path}")

    shares = results.get("shares", [])
    if shares:
        path = os.path.join(output_dir, "shares.txt")
        with open(path, "w") as f:
            for s in shares:
                f.write(f"{s['name']}\t{s['type']}\t{s['comment']}\n")
        good(f"Wrote {len(shares)} shares to {path}")

    pp = results.get("password_policy", {})
    if pp:
        path = os.path.join(output_dir, "policy.txt")
        with open(path, "w") as f:
            f.write(f"Minimum password length: {pp.get('min_length', '?')}\n")
            f.write(f"Password history:        {pp.get('history', '?')}\n")
            f.write(f"Maximum password age:     {pp.get('max_age', '?')}\n")
            f.write(f"Minimum password age:     {pp.get('min_age', '?')}\n")
            f.write(f"Complexity required:      {'Yes' if pp.get('complexity') else 'No'}\n")
            f.write(f"Lockout threshold:        {pp.get('lockout_threshold', '?')}\n")
            f.write(f"Lockout duration:         {pp.get('lockout_duration', '?')}\n")
            f.write(f"Lockout window:           {pp.get('lockout_window', '?')}\n")
        good(f"Wrote password policy to {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="nullsweep",
        description="Comprehensive null/anonymous session scanner for AD domain controllers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s example.com                           Discover DCs, test sessions
  %(prog)s example.com --rid-cycle                Also RID cycle for accounts
  %(prog)s example.com --dump                     Full enumeration dump
  %(prog)s example.com --dc dc01.example.com      Target a specific DC
  %(prog)s example.com --dc-file dcs.txt          DCs from a file
  %(prog)s example.com --rid-cycle --users-only   Just output usernames
  %(prog)s example.com --dump -o ./loot           Write output files
""",
    )

    p.add_argument("domain", help="Target AD domain (e.g. example.com)")

    target_group = p.add_argument_group("target selection")
    target_group.add_argument(
        "--dc", action="append", default=[],
        help="Target specific DC(s) — can be repeated",
    )
    target_group.add_argument(
        "--dc-file", metavar="FILE",
        help="Read DC hostnames from a file (one per line)",
    )
    target_group.add_argument(
        "--dns-server", metavar="IP",
        help="DNS server to use for DC discovery",
    )

    enum_group = p.add_argument_group("enumeration")
    enum_group.add_argument(
        "--rid-cycle", action="store_true",
        help="RID cycle to enumerate accounts",
    )
    enum_group.add_argument(
        "--dump", action="store_true",
        help="Full enumeration: users, groups, shares, policy, trusts",
    )
    enum_group.add_argument(
        "--max-rid", type=int, default=100000, metavar="N",
        help="Maximum RID to cycle to (default: 100000)",
    )
    enum_group.add_argument(
        "--batch-size", type=int, default=1000, metavar="N",
        help="RIDs per lookup batch (default: 1000, max: 1000)",
    )

    auth_group = p.add_argument_group("authentication (optional — defaults to null/anonymous/guest)")
    auth_group.add_argument("-u", "--username", default=None, help="Username")
    auth_group.add_argument("-p", "--password", default=None, help="Password")
    auth_group.add_argument("--hashes", default=None, metavar="LM:NT", help="NTLM hashes")

    output_group = p.add_argument_group("output")
    output_group.add_argument(
        "-o", "--output", metavar="DIR",
        help="Write output files (users.txt, groups.txt, etc.) to this directory",
    )
    output_group.add_argument(
        "--users-only", action="store_true",
        help="Only output usernames (one per line) — for password spraying",
    )
    output_group.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print full listings to stdout (default: summaries only, details in files)",
    )
    output_group.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )

    p.add_argument(
        "--timeout", type=int, default=10, metavar="SEC",
        help="Connection timeout in seconds (default: 10)",
    )
    p.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging",
    )
    p.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        C.disable()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    args.batch_size = min(args.batch_size, 1000)

    if not args.users_only:
        banner()

    # --- Resolve credentials ---
    creds = None
    if args.username is not None:
        password = args.password or ""
        creds = (args.username, password)

    # --- Discover or load DCs ---
    dcs = list(args.dc)

    if args.dc_file:
        try:
            with open(args.dc_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        dcs.append(line)
        except FileNotFoundError:
            bad(f"DC file not found: {args.dc_file}")
            sys.exit(1)

    if not dcs:
        if not args.users_only:
            info(f"Discovering domain controllers for {C.bold(args.domain)}...")
        dcs = discover_dcs(args.domain, args.dns_server)
        if not dcs:
            bad("No domain controllers found via DNS")
            bad("Try --dc <hostname> or --dc-file <file> to specify manually")
            sys.exit(1)
        if not args.users_only:
            good(f"Found {len(dcs)} DC(s) via DNS:")
            for dc in dcs:
                ip = resolve_host(dc)
                indent(f"{dc} ({ip or '?'})")

    # --- Scan each DC ---
    all_results = {}
    best_access = None
    best_dc = None
    best_ip = None

    for dc in dcs:
        ip = resolve_host(dc)
        target = ip or dc

        if not args.users_only:
            info(f"Scanning {dc}...")

        access = test_dc_access(target, args.domain, args.timeout, creds)

        if not args.users_only:
            print_access_results(dc, ip, access)

        all_results[dc] = access

        pipe_count = sum(1 for p in access["best"])
        if best_access is None or pipe_count > sum(1 for p in best_access["best"]):
            best_access = access
            best_dc = dc
            best_ip = ip

    if not best_access or not best_access["best"]:
        if not args.users_only:
            print()
            bad("No accessible pipes found on any DC")
        sys.exit(1)

    # --- Enumeration ---
    if args.rid_cycle or args.dump:
        target = best_ip or best_dc
        if not args.users_only:
            print()
            info(f"Using {C.bold(best_dc)} for enumeration (most accessible)")

        if args.dump:
            results = full_dump(
                best_access, target, args.domain,
                args.max_rid, args.batch_size,
            )
            if not args.users_only:
                print_dump_results(results, best_dc, verbose=args.verbose)

            if args.output:
                write_output_files(results, args.output, best_dc)

            if args.users_only:
                _print_users_only(results)

        elif args.rid_cycle:
            entries, method, domain_sid_str = rid_cycle(
                best_access, target, args.domain,
                args.max_rid, args.batch_size,
            )

            if args.users_only:
                if entries:
                    users, _, _, _, _ = categorize_entries(entries)
                    for e in sorted(users, key=lambda x: x.get("name", "")):
                        print(e["name"])
            else:
                if entries:
                    users, computers, svcaccts, groups, other = categorize_entries(entries)
                    print(f"\n{C.bold(f'--- Users ({len(users)}) ---')}")
                    for e in sorted(users, key=lambda x: x["rid"]):
                        print(f"  {e['rid']:<8d} {e['name']}")
                    if computers:
                        print(f"\n{C.bold(f'--- Computers ({len(computers)}) ---')}")
                        for e in sorted(computers, key=lambda x: x["rid"]):
                            print(f"  {e['rid']:<8d} {e['name']}")
                    if svcaccts:
                        print(f"\n{C.bold(f'--- Service Accounts ({len(svcaccts)}) ---')}")
                        for e in sorted(svcaccts, key=lambda x: x["rid"]):
                            print(f"  {e['rid']:<8d} {e['name']}")
                    if groups:
                        print(f"\n{C.bold(f'--- Groups ({len(groups)}) ---')}")
                        for e in sorted(groups, key=lambda x: x["rid"]):
                            print(f"  {e['rid']:<8d} {e['name']}")
                    print()

                if args.output and entries:
                    _write_rid_output(entries, args.output)

    # Cleanup
    for dc, access in all_results.items():
        for method, smb in access["smb_conns"].items():
            try:
                smb.logoff()
            except Exception:
                pass


def _print_users_only(results):
    """Print just usernames for password spraying — no machines, GUIDs, or groups."""
    seen = set()
    for u in results.get("users", []):
        name = u["name"]
        if not name.endswith("$") and not _is_service_account_guid(name) and name not in seen:
            print(name)
            seen.add(name)
    rid_entries = results.get("rid_entries", [])
    if rid_entries:
        users, _, _, _, _ = categorize_entries(rid_entries)
        for e in users:
            name = e["name"]
            if name not in seen:
                print(name)
                seen.add(name)


def _write_rid_output(entries, output_dir):
    """Write RID cycling results to files."""
    os.makedirs(output_dir, exist_ok=True)
    users, computers, svcaccts, groups, other = categorize_entries(entries)

    if users:
        path = os.path.join(output_dir, "users.txt")
        with open(path, "w") as f:
            for e in sorted(users, key=lambda x: x["name"]):
                f.write(f"{e['name']}\n")
        good(f"Wrote {len(users)} users to {path}")

    if computers:
        path = os.path.join(output_dir, "computers.txt")
        with open(path, "w") as f:
            for e in sorted(computers, key=lambda x: x["name"]):
                f.write(f"{e['name']}\n")
        good(f"Wrote {len(computers)} computers to {path}")

    if svcaccts:
        path = os.path.join(output_dir, "service_accounts.txt")
        with open(path, "w") as f:
            for e in sorted(svcaccts, key=lambda x: x["name"]):
                f.write(f"{e['name']}\n")
        good(f"Wrote {len(svcaccts)} service accounts to {path}")

    if groups:
        path = os.path.join(output_dir, "groups.txt")
        with open(path, "w") as f:
            for e in sorted(groups, key=lambda x: x["name"]):
                f.write(f"{e['name']}\n")
        good(f"Wrote {len(groups)} groups to {path}")

    if other:
        path = os.path.join(output_dir, "other.txt")
        with open(path, "w") as f:
            for e in sorted(other, key=lambda x: x["name"]):
                f.write(f"{e['name']}\n")
        good(f"Wrote {len(other)} uncategorized entries to {path}")


if __name__ == "__main__":
    main()
