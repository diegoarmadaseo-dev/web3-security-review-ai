#!/usr/bin/env python3
"""EVM Chain Catalog loader, validator, and capabilities resolver (V2.8,
docs/decisiones.md D-058).

Provides:
  - load_chains_config()      : load and deterministically validate config/chains.json
  - validate_chains_config()  : schema validation with strict duplicate detection
  - resolve_chain()           : resolve network name/alias/chainId to canonical identity
  - get_chain_capabilities()  : get capabilities for a chain without branching on names;
                                unknown chains return isKnown=False without guessed capabilities
  - ChainsConfigError         : raised on broken or invalid config

Standard library only. No network calls, no subprocesses. Python 3.8+.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

CATALOG_VERSION = "2026.1"

ALLOWED_TYPES = frozenset([
    "l1",
    "rollup-optimistic",
    "rollup-zk",
    "sidechain",
    "testnet",
    "appchain",
])

# Mirrors chains-schema.json's additionalProperties:false at each of its 3
# levels (root, chain entry, capabilities) - kept here as the single source
# validate_chains_config checks against, so validator and schema can never
# silently drift apart on which fields are allowed.
ALLOWED_ROOT_KEYS = frozenset(["$schema", "catalogVersion", "chains"])
ALLOWED_CHAIN_KEYS = frozenset(["chainId", "name", "aliases", "type", "evmVersion", "capabilities"])
ALLOWED_CAPABILITY_KEYS = frozenset(["supportsPush0", "supportsTransientStorage", "supportsCancun"])

NAME_RE = re.compile(r"^[a-z0-9-]+$")


class ChainsConfigError(ValueError):
    """Raised when chains configuration cannot be found, decoded, or validated."""


def _reject_unknown_keys(obj: Dict[str, Any], allowed: Set[str], where: str) -> None:
    unknown = sorted(set(obj.keys()) - allowed)
    if unknown:
        raise ChainsConfigError("%s has unrecognized field(s): %s" % (where, ", ".join(unknown)))


def default_chains_config_path() -> Path:
    """Find the default chains.json configuration file path."""
    current = Path(__file__).resolve()
    # 1. Skill config: <repo>/.claude/skills/web3-auditor/config/chains.json
    skill_config = current.parent.parent / "config" / "chains.json"
    if skill_config.is_file():
        return skill_config
    # 2. Workspace root config: <repo>/config/chains.json
    root_config = current.parent.parent.parent.parent.parent / "config" / "chains.json"
    if root_config.is_file():
        return root_config
    # Fallback to skill config path even if missing so error messages are consistent
    return skill_config


def validate_chains_config(data: Any) -> None:
    """Validate data against chains catalog schema rules deterministically.

    Raises ChainsConfigError on any structural or integrity violation.
    """
    if not isinstance(data, dict):
        raise ChainsConfigError("chains config must be a JSON object, got %s" % type(data).__name__)

    _reject_unknown_keys(data, ALLOWED_ROOT_KEYS, "chains config root")

    if "catalogVersion" not in data or not isinstance(data["catalogVersion"], str):
        raise ChainsConfigError("chains config missing required string field 'catalogVersion'")

    chains = data.get("chains")
    if not isinstance(chains, list):
        raise ChainsConfigError("chains config missing required array field 'chains'")

    seen_chain_ids: Set[int] = set()
    seen_identifiers: Set[str] = set()

    for idx, entry in enumerate(chains):
        if not isinstance(entry, dict):
            raise ChainsConfigError("chains[%d] must be an object" % idx)

        _reject_unknown_keys(entry, ALLOWED_CHAIN_KEYS, "chains[%d]" % idx)

        chain_id = entry.get("chainId")
        if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 1:
            raise ChainsConfigError(
                "chains[%d].chainId must be an integer >= 1, got %r" % (idx, chain_id)
            )

        if chain_id in seen_chain_ids:
            raise ChainsConfigError("duplicate chainId %d declared at chains[%d]" % (chain_id, idx))
        seen_chain_ids.add(chain_id)

        name = entry.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ChainsConfigError(
                "chains[%d].name must be a lowercase alphanumeric identifier, got %r" % (idx, name)
            )

        if name in seen_identifiers:
            raise ChainsConfigError(
                "duplicate network name or alias %r declared at chains[%d]" % (name, idx)
            )
        seen_identifiers.add(name)

        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list):
            raise ChainsConfigError("chains[%d].aliases must be a list of strings" % idx)

        for a_idx, alias in enumerate(aliases):
            if not isinstance(alias, str) or not NAME_RE.match(alias):
                raise ChainsConfigError(
                    "chains[%d].aliases[%d] must be a lowercase string, got %r" % (idx, a_idx, alias)
                )
            if alias in seen_identifiers:
                raise ChainsConfigError(
                    "duplicate network name or alias %r declared at chains[%d].aliases[%d]"
                    % (alias, idx, a_idx)
                )
            seen_identifiers.add(alias)

        chain_type = entry.get("type")
        if chain_type not in ALLOWED_TYPES:
            raise ChainsConfigError(
                "chains[%d].type must be one of %s, got %r"
                % (idx, sorted(ALLOWED_TYPES), chain_type)
            )

        evm_version = entry.get("evmVersion")
        if not isinstance(evm_version, str) or not evm_version.strip():
            raise ChainsConfigError("chains[%d].evmVersion must be a non-empty string" % idx)

        caps = entry.get("capabilities")
        if not isinstance(caps, dict):
            raise ChainsConfigError("chains[%d].capabilities must be an object" % idx)

        _reject_unknown_keys(caps, ALLOWED_CAPABILITY_KEYS, "chains[%d].capabilities" % idx)

        for cap_key in ("supportsPush0", "supportsTransientStorage"):
            if cap_key not in caps or not isinstance(caps[cap_key], bool):
                raise ChainsConfigError(
                    "chains[%d].capabilities.%s must be a boolean" % (idx, cap_key)
                )


_CONFIG_CACHE: Optional[Tuple[str, Dict[str, Any]]] = None


def load_chains_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load and validate the chains catalog from a JSON file.

    Raises ChainsConfigError on missing file, JSON decode error, or schema failure.
    """
    global _CONFIG_CACHE
    target_path = Path(path) if path else default_chains_config_path()
    path_str = str(target_path.resolve())

    if _CONFIG_CACHE is not None and _CONFIG_CACHE[0] == path_str and path is None:
        return _CONFIG_CACHE[1]

    if not target_path.is_file():
        raise ChainsConfigError("chains config file not found: %s" % path_str)

    try:
        raw_text = target_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except (OSError, json.JSONDecodeError) as exc:
        raise ChainsConfigError("failed to read/decode chains config %s: %s" % (path_str, exc)) from exc

    validate_chains_config(data)

    if path is None:
        _CONFIG_CACHE = (path_str, data)
    return data


def resolve_chain(
    network: Any,
    catalog: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """Resolve an incoming network identifier to (chainId, canonical_name_or_None, error_or_None).

    Deterministic resolution:
      - Integer or numeric string -> returns (int(network), canonical_name, None).
      - If integer is unknown in catalog -> returns (int(network), None, None) (R-I3).
      - Dict with {"chainId": N} -> resolves N recursively.
      - String name or alias -> resolved via catalog; if unresolvable -> (None, None, error).
      - Booleans or invalid types -> (None, None, error).
    """
    if network is None:
        return None, None, "network field absent or null"

    # Booleans inherit from int in Python; reject explicitly
    if isinstance(network, bool):
        return None, None, "network cannot be a boolean"

    # Unwrap {"chainId": N}
    if isinstance(network, dict):
        if "chainId" not in network:
            return None, None, "network object missing 'chainId' key"
        return resolve_chain(network["chainId"], catalog=catalog)

    config = catalog if catalog is not None else load_chains_config()

    # Build lookup maps from catalog
    chain_by_id: Dict[int, str] = {}
    id_by_name: Dict[str, int] = {}
    for entry in config.get("chains", []):
        c_id = entry["chainId"]
        c_name = entry["name"]
        chain_by_id[c_id] = c_name
        id_by_name[c_name] = c_id
        for alias in entry.get("aliases", []):
            id_by_name[alias] = c_id

    # Integer chainId
    if isinstance(network, int):
        return network, chain_by_id.get(network), None

    if isinstance(network, str):
        s = network.strip().lower()
        if s.isdigit():
            c_id = int(s)
            return c_id, chain_by_id.get(c_id), None
        if s in id_by_name:
            c_id = id_by_name[s]
            return c_id, chain_by_id.get(c_id), None
        return None, None, "unrecognized network name %r" % network

    return None, None, "network must be an integer chainId, numeric string, or recognized name"


def get_chain_capabilities(
    chain_id: int,
    catalog: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return capability flags and metadata for a chainId.

    If chain_id is not in the catalog, returns isKnown=False and empty capabilities
    without guessing or inventing capabilities (R-K3).
    """
    if not isinstance(chain_id, int) or isinstance(chain_id, bool):
        raise ValueError("chain_id must be an integer, got %r" % (chain_id,))

    config = catalog if catalog is not None else load_chains_config()

    for entry in config.get("chains", []):
        if entry.get("chainId") == chain_id:
            return {
                "chainId": chain_id,
                "name": entry.get("name"),
                "type": entry.get("type"),
                "evmVersion": entry.get("evmVersion"),
                "capabilities": dict(entry.get("capabilities", {})),
                "isKnown": True,
            }

    # Unknown chain: representation without guessed capabilities
    return {
        "chainId": chain_id,
        "name": None,
        "type": "unknown",
        "evmVersion": None,
        "capabilities": {},
        "isKnown": False,
    }
