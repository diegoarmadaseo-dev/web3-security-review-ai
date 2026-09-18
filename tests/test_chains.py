"""Tests for EVM Multi-Chain Catalog, Capabilities, and Cross-Chain Isolation
(V2.8, docs/decisiones.md D-058).

Run from repository root: python -m unittest
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor"
SCRIPTS_DIR = SKILL_DIR / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import chains  # noqa: E402
import ingest_onchain  # noqa: E402
import preprocess  # noqa: E402

REFERENCES_DIR = SKILL_DIR / "references"
REAL_CONFIG_PATH = str(SKILL_DIR / "config" / "chains.json")

ADDR_SHARED = "0x1111111111111111111111111111111111111111"


def _write_temp_config(tmp_dir: str, data: Any) -> str:
    path = os.path.join(tmp_dir, "chains.json")
    with open(path, "w", encoding="utf-8") as f:
        if isinstance(data, str):
            f.write(data)
        else:
            json.dump(data, f)
    return path


class ChainsCatalogLoadingAndValidationTests(unittest.TestCase):
    def test_real_config_loads_cleanly(self):
        catalog = chains.load_chains_config(REAL_CONFIG_PATH)
        self.assertEqual(catalog["catalogVersion"], "2026.1")
        self.assertGreaterEqual(len(catalog["chains"]), 11)

    def test_missing_config_raises_error(self):
        with self.assertRaises(chains.ChainsConfigError):
            chains.load_chains_config("nonexistent_path_chains.json")

    def test_broken_json_raises_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, "{not valid json")
            with self.assertRaises(chains.ChainsConfigError):
                chains.load_chains_config(p)

    def test_non_dict_config_raises_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, ["not", "a", "dict"])
            with self.assertRaises(chains.ChainsConfigError):
                chains.load_chains_config(p)

    def test_missing_catalog_version_raises_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, {"chains": []})
            with self.assertRaises(chains.ChainsConfigError):
                chains.load_chains_config(p)

    def test_duplicate_chain_id_raises_error(self):
        data = {
            "catalogVersion": "2026.1",
            "chains": [
                {
                    "chainId": 1,
                    "name": "ethereum",
                    "type": "l1",
                    "evmVersion": "cancun",
                    "capabilities": {"supportsPush0": True, "supportsTransientStorage": True},
                },
                {
                    "chainId": 1,
                    "name": "ethereum-dup",
                    "type": "l1",
                    "evmVersion": "cancun",
                    "capabilities": {"supportsPush0": True, "supportsTransientStorage": True},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("duplicate chainId", str(ctx.exception))

    def test_duplicate_name_raises_error(self):
        data = {
            "catalogVersion": "2026.1",
            "chains": [
                {
                    "chainId": 1,
                    "name": "ethereum",
                    "type": "l1",
                    "evmVersion": "cancun",
                    "capabilities": {"supportsPush0": True, "supportsTransientStorage": True},
                },
                {
                    "chainId": 2,
                    "name": "ethereum",
                    "type": "l1",
                    "evmVersion": "cancun",
                    "capabilities": {"supportsPush0": True, "supportsTransientStorage": True},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("duplicate network name", str(ctx.exception))

    def test_duplicate_alias_across_chains_raises_error(self):
        data = {
            "catalogVersion": "2026.1",
            "chains": [
                {
                    "chainId": 1,
                    "name": "ethereum",
                    "aliases": ["mainnet"],
                    "type": "l1",
                    "evmVersion": "cancun",
                    "capabilities": {"supportsPush0": True, "supportsTransientStorage": True},
                },
                {
                    "chainId": 10,
                    "name": "optimism",
                    "aliases": ["mainnet"],
                    "type": "rollup-optimistic",
                    "evmVersion": "canyon",
                    "capabilities": {"supportsPush0": True, "supportsTransientStorage": False},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("duplicate network name or alias", str(ctx.exception))

    def test_invalid_chain_type_raises_error(self):
        data = {
            "catalogVersion": "2026.1",
            "chains": [
                {
                    "chainId": 1,
                    "name": "ethereum",
                    "type": "not-a-valid-type",
                    "evmVersion": "cancun",
                    "capabilities": {"supportsPush0": True, "supportsTransientStorage": True},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("type must be one of", str(ctx.exception))

    def test_missing_or_non_boolean_capabilities_raises_error(self):
        data = {
            "catalogVersion": "2026.1",
            "chains": [
                {
                    "chainId": 1,
                    "name": "ethereum",
                    "type": "l1",
                    "evmVersion": "cancun",
                    "capabilities": {"supportsPush0": "yes", "supportsTransientStorage": True},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("must be a boolean", str(ctx.exception))

    def _valid_chain_entry(self):
        return {
            "chainId": 1,
            "name": "ethereum",
            "type": "l1",
            "evmVersion": "cancun",
            "capabilities": {"supportsPush0": True, "supportsTransientStorage": True},
        }

    def test_unknown_root_field_raises_error(self):
        data = {"catalogVersion": "2026.1", "chains": [self._valid_chain_entry()], "unexpectedRootField": True}
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("unrecognized field", str(ctx.exception))
            self.assertIn("unexpectedRootField", str(ctx.exception))

    def test_known_root_field_schema_is_still_accepted(self):
        # $schema is a declared-optional root property (chains-schema.json)
        # and IS present in the real config/chains.json - must never be
        # rejected as "unrecognized".
        data = {"$schema": "../references/chains-schema.json", "catalogVersion": "2026.1", "chains": [self._valid_chain_entry()]}
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            catalog = chains.load_chains_config(p)
        self.assertEqual(catalog["catalogVersion"], "2026.1")

    def test_unknown_chain_entry_field_raises_error(self):
        entry = self._valid_chain_entry()
        entry["unexpectedChainField"] = "anything"
        data = {"catalogVersion": "2026.1", "chains": [entry]}
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("unrecognized field", str(ctx.exception))
            self.assertIn("unexpectedChainField", str(ctx.exception))

    def test_unknown_capabilities_field_raises_error(self):
        entry = self._valid_chain_entry()
        entry["capabilities"] = dict(entry["capabilities"], unexpectedCapField=True)
        data = {"catalogVersion": "2026.1", "chains": [entry]}
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            with self.assertRaises(chains.ChainsConfigError) as ctx:
                chains.load_chains_config(p)
            self.assertIn("unrecognized field", str(ctx.exception))
            self.assertIn("unexpectedCapField", str(ctx.exception))

    def test_known_optional_capability_supports_cancun_is_still_accepted(self):
        # supportsCancun is a declared-optional capabilities property and IS
        # present on every entry in the real config/chains.json - must never
        # be rejected as "unrecognized".
        entry = self._valid_chain_entry()
        entry["capabilities"] = dict(entry["capabilities"], supportsCancun=True)
        data = {"catalogVersion": "2026.1", "chains": [entry]}
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            catalog = chains.load_chains_config(p)
        self.assertTrue(catalog["chains"][0]["capabilities"]["supportsCancun"])

    def test_known_optional_aliases_field_is_still_accepted(self):
        entry = self._valid_chain_entry()
        entry["aliases"] = ["mainnet"]
        data = {"catalogVersion": "2026.1", "chains": [entry]}
        with tempfile.TemporaryDirectory() as tmp:
            p = _write_temp_config(tmp, data)
            catalog = chains.load_chains_config(p)
        self.assertEqual(catalog["chains"][0]["aliases"], ["mainnet"])


class ChainResolutionTests(unittest.TestCase):
    def test_resolves_integer_chain_id(self):
        c_id, name, err = chains.resolve_chain(1)
        self.assertEqual((c_id, name, err), (1, "ethereum", None))

        c_id, name, err = chains.resolve_chain(137)
        self.assertEqual((c_id, name, err), (137, "polygon", None))

    def test_resolves_numeric_string(self):
        c_id, name, err = chains.resolve_chain("8453")
        self.assertEqual((c_id, name, err), (8453, "base", None))

    def test_resolves_dict_with_chain_id(self):
        c_id, name, err = chains.resolve_chain({"chainId": 42161})
        self.assertEqual((c_id, name, err), (42161, "arbitrum", None))

    def test_resolves_canonical_name_case_insensitively(self):
        c_id, name, err = chains.resolve_chain("OPTIMISM")
        self.assertEqual((c_id, name, err), (10, "optimism", None))

    def test_resolves_aliases(self):
        c_id, name, err = chains.resolve_chain("matic")
        self.assertEqual((c_id, name, err), (137, "polygon", None))

        c_id, name, err = chains.resolve_chain("xdai")
        self.assertEqual((c_id, name, err), (100, "gnosis", None))

    def test_unknown_numeric_chain_id_is_accepted_without_error(self):
        c_id, name, err = chains.resolve_chain(999999)
        self.assertEqual(c_id, 999999)
        self.assertIsNone(name)
        self.assertIsNone(err)

    def test_rejects_boolean(self):
        c_id, name, err = chains.resolve_chain(True)
        self.assertIsNone(c_id)
        self.assertIn("boolean", err)

    def test_rejects_unrecognized_string_name(self):
        c_id, name, err = chains.resolve_chain("not-a-chain")
        self.assertIsNone(c_id)
        self.assertIn("unrecognized", err)


class CapabilitiesResolutionTests(unittest.TestCase):
    def test_known_chain_capabilities(self):
        meta = chains.get_chain_capabilities(1)
        self.assertTrue(meta["isKnown"])
        self.assertEqual(meta["chainId"], 1)
        self.assertEqual(meta["name"], "ethereum")
        self.assertEqual(meta["type"], "l1")
        self.assertTrue(meta["capabilities"]["supportsPush0"])
        self.assertTrue(meta["capabilities"]["supportsTransientStorage"])

    def test_fantom_paris_capabilities(self):
        meta = chains.get_chain_capabilities(250)
        self.assertTrue(meta["isKnown"])
        self.assertEqual(meta["name"], "fantom")
        self.assertFalse(meta["capabilities"]["supportsPush0"])
        self.assertFalse(meta["capabilities"]["supportsTransientStorage"])

    def test_unknown_chain_capabilities_are_empty_without_guessing(self):
        meta = chains.get_chain_capabilities(999999)
        self.assertFalse(meta["isKnown"])
        self.assertEqual(meta["chainId"], 999999)
        self.assertIsNone(meta["name"])
        self.assertEqual(meta["type"], "unknown")
        self.assertIsNone(meta["evmVersion"])
        self.assertEqual(meta["capabilities"], {})

    def test_invalid_type_raises_value_error(self):
        with self.assertRaises(ValueError):
            chains.get_chain_capabilities(True)  # type: ignore
        with self.assertRaises(ValueError):
            chains.get_chain_capabilities("1")  # type: ignore


def _process_bundle_helper(bundle_text: str, mode: str = "pro") -> Dict[str, Any]:
    entries = preprocess.collect_inputs([], stdin_text=bundle_text)
    processed = [preprocess.process_entry(e) for e in entries]
    limits = preprocess.resolve_limits(mode, None)
    flags = preprocess.resolve_feature_flags(mode)
    return preprocess.build_artifact(
        processed,
        mode=mode,
        limits=limits,
        include_timestamp=False,
        allow_system_graph=flags["allowSystemGraph"],
    )


class MultiChainIsolationTests(unittest.TestCase):
    def test_same_address_in_two_chains_has_distinct_virtual_prefixes(self):
        raw_eth = {
            "address": ADDR_SHARED,
            "network": "ethereum",
            "verified": True,
            "sourceFiles": [{"path": "Vault.sol", "content": "contract Vault {}"}],
        }
        raw_poly = {
            "address": ADDR_SHARED,
            "network": "polygon",
            "verified": True,
            "sourceFiles": [{"path": "Vault.sol", "content": "contract Vault {}"}],
        }

        rec_eth = ingest_onchain.ingest(raw_eth)
        rec_poly = ingest_onchain.ingest(raw_poly)

        self.assertEqual(rec_eth["virtualPathPrefix"], "onchain://1/%s/" % ADDR_SHARED)
        self.assertEqual(rec_poly["virtualPathPrefix"], "onchain://137/%s/" % ADDR_SHARED)
        self.assertNotEqual(rec_eth["virtualPathPrefix"], rec_poly["virtualPathPrefix"])

    def test_multichain_simultaneous_bundle_isolation(self):
        # Multi-chain bundle with same contract name and address in two different chains
        bundle_content = (
            "=== FILE: onchain://1/%s/Vault.sol ===\n"
            "pragma solidity 0.8.20;\n"
            "contract Vault { function chain() external pure returns (uint) { return 1; } }\n"
            "=== END FILE ===\n"
            "=== FILE: onchain://137/%s/Vault.sol ===\n"
            "pragma solidity 0.8.20;\n"
            "contract Vault { function chain() external pure returns (uint) { return 137; } }\n"
            "=== END FILE ===\n"
        ) % (ADDR_SHARED, ADDR_SHARED)

        artifact = _process_bundle_helper(bundle_content, mode="pro")
        self.assertIn("contracts", artifact)

        keys = [c["key"] for c in artifact["contracts"]]
        expected_eth_key = "onchain:/1/%s/Vault.sol#Vault" % ADDR_SHARED
        expected_poly_key = "onchain:/137/%s/Vault.sol#Vault" % ADDR_SHARED

        self.assertIn(expected_eth_key, keys)
        self.assertIn(expected_poly_key, keys)
        self.assertEqual(len(keys), 2)

        # In systemGraph.nodes, both exist as distinct nodes
        sg_nodes = {n["key"] for n in artifact["systemGraph"]["nodes"]}
        self.assertIn(expected_eth_key, sg_nodes)
        self.assertIn(expected_poly_key, sg_nodes)

    def test_proxies_isolated_by_chain_never_cross_bind(self):
        # Bundle with Proxy on Chain 1 and Implementation on Chain 137 only.
        # Must NOT bind across chains! Proxy.sol declares ONLY Proxy - no local
        # stub named "Implementation" - so chain 1 has zero same-chain
        # candidates for the referenced type; preprocess.py's structural
        # state-variable parser extracts userType="Implementation" from the
        # declaration itself, it does not require the type to be declared
        # anywhere for parsing to succeed.
        proxy_code = (
            "pragma solidity 0.8.20;\n"
            "contract Proxy {\n"
            "    Implementation internal impl;\n"
            "    fallback() external payable {\n"
            "        (bool ok, ) = impl.delegatecall(msg.data);\n"
            "        require(ok);\n"
            "    }\n"
            "}\n"
        )
        impl_code = "pragma solidity 0.8.20;\ncontract Implementation {}\n"

        bundle_content = (
            "=== FILE: onchain://1/%s/Proxy.sol ===\n%s\n=== END FILE ===\n"
            "=== FILE: onchain://137/%s/Implementation.sol ===\n%s\n=== END FILE ===\n"
        ) % (ADDR_SHARED, proxy_code, ADDR_SHARED, impl_code)

        artifact = _process_bundle_helper(bundle_content, mode="pro")
        proxies = artifact["systemGraph"]["proxies"]
        self.assertEqual(len(proxies), 1)
        # Must stay unresolved because Implementation is on chain 137, while Proxy is on chain 1
        self.assertEqual(proxies[0]["status"], "unresolved")
        self.assertIsNone(proxies[0]["implementation"])
        self.assertIn("matches 0 contracts", proxies[0]["reason"])

    def test_proxies_on_different_chains_each_bind_to_own_chain(self):
        # Chain 1 has Proxy + Impl1; Chain 137 has Proxy + Impl137. Proxy.sol
        # declares ONLY Proxy per chain (see comment above) so each chain has
        # exactly one same-chain "Impl" candidate: its own dedicated Impl.sol.
        proxy_code = (
            "pragma solidity 0.8.20;\n"
            "contract Proxy {\n"
            "    Impl internal impl;\n"
            "    fallback() external payable {\n"
            "        (bool ok, ) = impl.delegatecall(msg.data);\n"
            "        require(ok);\n"
            "    }\n"
            "}\n"
        )
        impl_code = "pragma solidity 0.8.20;\ncontract Impl {}\n"

        bundle_content = (
            "=== FILE: onchain://1/%s/Proxy.sol ===\n%s\n=== END FILE ===\n"
            "=== FILE: onchain://1/%s/Impl.sol ===\n%s\n=== END FILE ===\n"
            "=== FILE: onchain://137/%s/Proxy.sol ===\n%s\n=== END FILE ===\n"
            "=== FILE: onchain://137/%s/Impl.sol ===\n%s\n=== END FILE ===\n"
        ) % (ADDR_SHARED, proxy_code, ADDR_SHARED, impl_code, ADDR_SHARED, proxy_code, ADDR_SHARED, impl_code)

        artifact = _process_bundle_helper(bundle_content, mode="pro")
        proxies = artifact["systemGraph"]["proxies"]
        self.assertEqual(len(proxies), 2)

        # Both proxies resolve to their respective on-chain implementation without collision
        resolved = {p["proxy"]: p["implementation"] for p in proxies if p["status"] == "resolved"}
        self.assertEqual(len(resolved), 2)
        self.assertEqual(
            resolved["onchain:/1/%s/Proxy.sol#Proxy" % ADDR_SHARED],
            "onchain:/1/%s/Impl.sol#Impl" % ADDR_SHARED,
        )
        self.assertEqual(
            resolved["onchain:/137/%s/Proxy.sol#Proxy" % ADDR_SHARED],
            "onchain:/137/%s/Impl.sol#Impl" % ADDR_SHARED,
        )

    def test_ambiguous_same_chain_candidates_stay_unresolved(self):
        # Chain 1 has Proxy referencing type "Impl", and TWO separate files
        # (ImplA.sol, ImplB.sol) each genuinely declaring "contract Impl {}"
        # on that SAME chain - real ambiguity, unrelated to cross-chain
        # isolation. Must stay unresolved: never guess between 2 candidates,
        # exactly the same "need exactly 1 to bind" rule this feature has
        # always applied, now confirmed to still hold within one chain.
        proxy_code = (
            "pragma solidity 0.8.20;\n"
            "contract Proxy {\n"
            "    Impl internal impl;\n"
            "    fallback() external payable {\n"
            "        (bool ok, ) = impl.delegatecall(msg.data);\n"
            "        require(ok);\n"
            "    }\n"
            "}\n"
        )
        impl_code = "pragma solidity 0.8.20;\ncontract Impl {}\n"

        bundle_content = (
            "=== FILE: onchain://1/%s/Proxy.sol ===\n%s\n=== END FILE ===\n"
            "=== FILE: onchain://1/%s/ImplA.sol ===\n%s\n=== END FILE ===\n"
            "=== FILE: onchain://1/%s/ImplB.sol ===\n%s\n=== END FILE ===\n"
        ) % (ADDR_SHARED, proxy_code, ADDR_SHARED, impl_code, ADDR_SHARED, impl_code)

        artifact = _process_bundle_helper(bundle_content, mode="pro")
        proxies = artifact["systemGraph"]["proxies"]
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0]["status"], "unresolved")
        self.assertIsNone(proxies[0]["implementation"])
        self.assertIn("matches 2 contracts", proxies[0]["reason"])


class SchemaDriftTests(unittest.TestCase):
    def test_config_matches_schema_properties(self):
        schema = json.loads((REFERENCES_DIR / "chains-schema.json").read_text(encoding="utf-8"))
        catalog = json.loads(Path(REAL_CONFIG_PATH).read_text(encoding="utf-8"))

        self.assertTrue(set(schema["required"]).issubset(set(catalog.keys())))

        chain_req = set(schema["properties"]["chains"]["items"]["required"])
        cap_req = set(schema["properties"]["chains"]["items"]["properties"]["capabilities"]["required"])

        for chain in catalog["chains"]:
            self.assertTrue(chain_req.issubset(set(chain.keys())))
            self.assertTrue(cap_req.issubset(set(chain["capabilities"].keys())))


if __name__ == "__main__":
    unittest.main()
