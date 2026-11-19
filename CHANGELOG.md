# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Semantic drift and circular reasoning detector (`SemanticDriftDetector`) with pluggable embedder and stdlib fallback ([#30](https://github.com/Agentboxx-dev/Agentboxx/issues/30))
- `analysis.signal` events for `semantic_loop` and `goal_drift`
- Optional `embeddings` extra (`fastembed>=0.2.0`) in `pyproject.toml`
- Comprehensive detection guide in `docs/detection.md` and FAQ in README

## [0.3.1] - 2026-11-01

### Changed
- Release version bump to 0.3.1 and dependency policy alignment
- SECURITY.md vulnerability reporting policy, refreshed architecture diagram, and documented threat model ([#57](https://github.com/Agentboxx-dev/Agentboxx/issues/57))

## [0.3.0] - 2026-10-01

### Added
- First-class MCP and function tool-call recording with payload capping (`tool.call` events, `record_tool_call` API) ([#50](https://github.com/Agentboxx-dev/Agentboxx/issues/50))
- Self-contained signed evidence bundles for offline auditing (`agentbox bundle`) ([#33](https://github.com/Agentboxx-dev/Agentboxx/issues/33))
- Error-signature extractors for Rust, Java, and Ruby ([#11](https://github.com/Agentboxx-dev/Agentboxx/issues/11))
- Interactive terminal replay for agent sessions with autoplay and tamper verdict banners (`agentbox replay`) ([#29](https://github.com/Agentboxx-dev/Agentboxx/issues/29))
- Network egress filtering proxy with domain allowlisting and signed connection audit events ([#24](https://github.com/Agentboxx-dev/Agentboxx/issues/24))
- Safe file assertions in task contracts rejecting symlinks, FIFOs, and path traversal ([#55](https://github.com/Agentboxx-dev/Agentboxx/issues/55))
- Contract `assert_command` runs inside clean, ephemeral sandboxes ([#54](https://github.com/Agentboxx-dev/Agentboxx/issues/54))
- RFC 8032 Ed25519 test vectors and comprehensive negative verification test coverage ([#47](https://github.com/Agentboxx-dev/Agentboxx/issues/47))

## [0.2.1] - 2026-08-01

### Added
- Standalone Go log and Ed25519 receipt verifier (`verifiers/go`) ([#42](https://github.com/Agentboxx-dev/Agentboxx/issues/42))
- Live model execution support for Gemini 2.5/3.5 thinking tokens and platform hints ([#40](https://github.com/Agentboxx-dev/Agentboxx/issues/40))
- Public-key signing using Ed25519 so third parties can verify logs ([#23](https://github.com/Agentboxx-dev/Agentboxx/issues/23))
- Live Model Execution and Task Contracts quickstart guides

## [0.2.0] - 2026-06-01

### Added
- Hardened Docker sandbox backend with read-only rootfs, dropped capabilities, non-root user, and resource limits
- Task Contracts with step budgets, duration limits, deadlines, and file assertions
- Sandbox resource sampling (`sandbox.resource`) and container crash/OOM events (`sandbox.crash`)
- Interactive session replay UI prototype
- Secret redaction before signing for API keys, bearer tokens, private keys, and passwords

## [0.1.0] - 2026-04-01

### Added
- Initial release of Agentboxx
- Tamper-evident hash-chained event log with HMAC signatures (`signer.py`)
- ReAct-style agent loop wired to host-side recorder (`agent.py`)
- State-aware loop detector with hint feedback for repeated commands, errors, and cycles (`loop_detector.py`)
- CLI commands: `agentbox verify`, `agentbox report`, `agentbox list`, `agentbox demo`
- Process-tree termination and output size limits on runaway commands
