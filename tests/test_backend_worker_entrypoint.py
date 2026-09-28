#!/usr/bin/env python3
"""Focused tests for backend/worker_entrypoint.py's provider-selection
logic (docs/decisiones.md, the phase that wired the already-validated
DeepSeekLLMProvider into the real worker path). No prior test file for
this module existed - confirmed by a repo-wide search before writing this;
this module's full container-lifecycle behavior is exercised for real by
tests/test_backend_worker_supervisor.py's Docker-gated integration tests
instead (mock_responses envelope path). This file is narrowly about
_select_provider() - which concrete backend.llm_client provider class
gets constructed for which LLM_PROVIDER value - tested with a fake
llm_client-shaped module (mock.MagicMock) rather than the real one, so no
real network call, and no dependency on the anthropic/openai packages
being installed in this environment.

Run from the repository root: python -m unittest
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import backend.llm_client as llm_client  # noqa: E402  (only for the real LLMError class)
import backend.worker_entrypoint as worker_entrypoint  # noqa: E402


class SelectProviderTests(unittest.TestCase):
    """_select_provider(llm_client_module, provider_name, api_key, model)
    is a pure dispatch function - these tests use a fake llm_client-shaped
    module so they never construct a real AnthropicLLMProvider/
    DeepSeekLLMProvider (which would need the anthropic/openai SDKs
    installed) and never touch the network."""

    def _fake_llm_client_module(self):
        fake = mock.MagicMock()
        fake.LLMError = llm_client.LLMError  # the real exception class, so assertRaises works genuinely
        return fake

    def test_anthropic_is_the_default_behavior_preserved(self):
        # Byte-identical to every deployment that has never set
        # LLM_PROVIDER at all - see worker_entrypoint.py's own
        # os.environ.get("LLM_PROVIDER", "anthropic") default.
        fake_module = self._fake_llm_client_module()
        worker_entrypoint._select_provider(fake_module, "anthropic", "fake-key", "claude-model")
        fake_module.AnthropicLLMProvider.assert_called_once_with(api_key="fake-key", model="claude-model")
        fake_module.DeepSeekLLMProvider.assert_not_called()

    def test_deepseek_constructs_the_real_deepseek_provider_class(self):
        fake_module = self._fake_llm_client_module()
        worker_entrypoint._select_provider(fake_module, "deepseek", "fake-key", "deepseek-flash")
        fake_module.DeepSeekLLMProvider.assert_called_once_with(api_key="fake-key", model="deepseek-flash")
        fake_module.AnthropicLLMProvider.assert_not_called()

    def test_unknown_provider_fails_closed_with_a_clear_error(self):
        fake_module = self._fake_llm_client_module()
        with self.assertRaises(llm_client.LLMError) as ctx:
            worker_entrypoint._select_provider(fake_module, "some-other-vendor", "fake-key", "model-x")
        self.assertIn("unknown LLM_PROVIDER", str(ctx.exception))
        self.assertIn("some-other-vendor", str(ctx.exception))

    def test_unknown_provider_never_constructs_any_real_provider(self):
        fake_module = self._fake_llm_client_module()
        with self.assertRaises(llm_client.LLMError):
            worker_entrypoint._select_provider(fake_module, "bogus", "fake-key", "model-x")
        fake_module.AnthropicLLMProvider.assert_not_called()
        fake_module.DeepSeekLLMProvider.assert_not_called()

    def test_empty_string_provider_name_also_fails_closed(self):
        # Never silently treated as "unset" (which would mean "anthropic")
        # - only main()'s own os.environ.get default does that; an
        # explicit empty value reaching this function is a real
        # misconfiguration, not "no opinion".
        fake_module = self._fake_llm_client_module()
        with self.assertRaises(llm_client.LLMError):
            worker_entrypoint._select_provider(fake_module, "", "fake-key", "model-x")

    def test_api_key_and_model_are_forwarded_exactly_for_both_providers(self):
        fake_module = self._fake_llm_client_module()
        worker_entrypoint._select_provider(fake_module, "anthropic", "key-A", "model-A")
        worker_entrypoint._select_provider(fake_module, "deepseek", "key-B", "model-B")
        fake_module.AnthropicLLMProvider.assert_called_once_with(api_key="key-A", model="model-A")
        fake_module.DeepSeekLLMProvider.assert_called_once_with(api_key="key-B", model="model-B")

    def test_underlying_provider_construction_error_propagates_unchanged(self):
        # A real credential/package error from the provider's own
        # constructor (e.g. missing api_key) must reach the caller as-is,
        # not be swallowed or reworded by the dispatch itself.
        fake_module = self._fake_llm_client_module()
        fake_module.DeepSeekLLMProvider.side_effect = llm_client.LLMError("api_key is required")
        with self.assertRaises(llm_client.LLMError) as ctx:
            worker_entrypoint._select_provider(fake_module, "deepseek", "", "deepseek-flash")
        self.assertEqual(str(ctx.exception), "api_key is required")


class WorkerConfigProviderFieldTests(unittest.TestCase):
    """backend.worker_supervisor.WorkerConfig/build_docker_create_args -
    the host-side half of getting LLM_PROVIDER into the container's own
    environment (see backend/worker_entrypoint.py's PROVIDER SELECTION
    docstring section for the full chain: main.py's cfg -> WorkerConfig ->
    build_docker_create_args's -e flags -> this module reads it back)."""

    def _config(self, **overrides):
        import backend.worker_supervisor as ws
        defaults = dict(
            docker_image="img", network_name="net", proxy_host="127.0.0.1", proxy_port=1,
            llm_api_key="k", llm_model="m",
        )
        defaults.update(overrides)
        return ws.WorkerConfig(**defaults)

    def test_llm_provider_defaults_to_anthropic(self):
        config = self._config()
        self.assertEqual(config.llm_provider, "anthropic")

    def test_llm_provider_override_is_stored(self):
        config = self._config(llm_provider="deepseek")
        self.assertEqual(config.llm_provider, "deepseek")

    def test_docker_create_args_include_llm_provider_env_var(self):
        import backend.worker_supervisor as ws
        config = self._config(llm_provider="deepseek")
        args = ws.build_docker_create_args(config, "test-container")
        self.assertIn("LLM_PROVIDER=deepseek", args)

    def test_default_config_produces_anthropic_env_var(self):
        import backend.worker_supervisor as ws
        args = ws.build_docker_create_args(self._config(), "test-container")
        self.assertIn("LLM_PROVIDER=anthropic", args)

    def test_no_blanket_environment_dump_only_the_known_curated_set(self):
        # build_docker_create_args() must keep passing an explicit, bounded
        # list of -e flags - never widen to dumping the whole host
        # environment into the container. An unrelated env var this
        # process happens to have set must never appear in the args.
        import backend.worker_supervisor as ws
        with mock.patch.dict(os.environ, {"SOME_UNRELATED_HOST_SECRET": "should-never-leak-xyz123"}):
            args = ws.build_docker_create_args(self._config(llm_provider="deepseek"), "test-container")
        self.assertNotIn("SOME_UNRELATED_HOST_SECRET", " ".join(args))
        self.assertNotIn("should-never-leak-xyz123", " ".join(args))
        env_flags = {args[i + 1].split("=", 1)[0] for i, a in enumerate(args) if a == "-e"}
        self.assertEqual(
            env_flags,
            {"HTTPS_PROXY", "SOURCE_PATH", "LLM_MODEL", "LLM_PROVIDER", "LLM_MAX_OUTPUT_TOKENS", "LLM_PER_ATTEMPT_TIMEOUT_SECONDS"},
        )

    def test_llm_api_key_never_appears_in_docker_create_args(self):
        # The credential travels via the stdin envelope only (see
        # backend/worker_supervisor.py's own CREDENTIAL HANDLING docstring
        # section) - build_docker_create_args() must never embed it as an
        # -e flag, which would make it visible to `docker inspect`.
        import backend.worker_supervisor as ws
        config = self._config(llm_api_key="sk-should-never-appear-in-argv-999")
        args = ws.build_docker_create_args(config, "test-container")
        self.assertNotIn("sk-should-never-appear-in-argv-999", " ".join(args))


if __name__ == "__main__":
    unittest.main()
