import unittest
import hashlib
import json
import time

from orderstream_mesh import (
    MVCCIndexBTree, BitmapCommitGraph, FastCDCChunker, UnicodeCaseFoldingGate,
    SubmoduleTransactionCoordinator, SATMergeSolver, ContractHypergraph, MerkleRedactionEngine,
    ActionContextTaintEngine, CacheAttestationEngine, WasmCompilationServer, CRIUPreemptionManager,
    SLSAProvenanceEngine, MerkleTimestampAuthority, MicroPatchSynthesizer, SMTReachabilitySolver,
    GitOpsLensReconciler, APITrafficShaper, CRDTGitStorageEngine, SemanticASTBlameTracker,
    DynamicContextPolicyEngine, BehavioralFuzzSandbox, DynamicStateDiffEngine, SCIPSymbolIndexer
)

class TestOrderStreamMesh24Solvers(unittest.TestCase):

    # ---------------------------------------------------------
    # Pillar 1 Tests: VCS Storage Engine & Kernel Boundaries
    # ---------------------------------------------------------
    def test_01_mvcc_index_btree(self):
        tree = MVCCIndexBTree()
        v1 = tree.commit_transaction({"src/main.rs": "sha_v1", "README.md": "sha_readme"})
        self.assertEqual(v1, 1)
        self.assertEqual(tree.get_at_version("src/main.rs", 1), "sha_v1")

        # Mutate in v2
        v2 = tree.commit_transaction({"src/main.rs": "sha_v2"}, deleted=["README.md"])
        self.assertEqual(v2, 2)
        self.assertEqual(tree.get_at_version("src/main.rs", 2), "sha_v2")
        self.assertIsNone(tree.get_at_version("README.md", 2))
        # v1 snapshot remains immutable
        self.assertEqual(tree.get_at_version("src/main.rs", 1), "sha_v1")

        # O(1) status check
        status = tree.status_o1()
        self.assertEqual(status["version"], 2)
        self.assertTrue(status["dirty_count"] >= 2)

    def test_02_bitmap_commit_graph(self):
        graph = BitmapCommitGraph()
        graph.add_commit("c1", [])
        graph.add_commit("c2", ["c1"])
        graph.add_commit("c3", ["c2"])
        graph.register_ref("refs/pull/42/head", "c3")

        # Edge fetch proxy negotiation with Merkle sub-DAG filtering
        target_sha, needed = graph.filter_sub_dag_ad("refs/pull/42/head", client_haves={"c1"})
        self.assertEqual(target_sha, {"c3"})
        self.assertEqual(needed, {"c2", "c3"})

    def test_03_fastcdc_chunker(self):
        chunker = FastCDCChunker(min_size=16, avg_size=32, max_size=64)
        data = b"Enterprise Git LFS binary stream payload for high-speed content-defined chunking test " * 20
        chunks = chunker.chunk_stream(data)
        self.assertTrue(len(chunks) > 1)
        total_len = sum(c["size"] for c in chunks)
        self.assertEqual(total_len, len(data))
        merkle_root = chunker.compute_merkle_root(chunks)
        self.assertEqual(len(merkle_root), 64)

    def test_04_unicode_case_folding_gate(self):
        paths_clean = ["src/Config.go", "src/models/User.go"]
        res_clean = UnicodeCaseFoldingGate.inspect_tree_collision(paths_clean)
        self.assertTrue(res_clean["passed"])

        # Collision detection (macOS / Windows collision)
        paths_collision = ["src/Config.go", "src/config.go"]
        res_col = UnicodeCaseFoldingGate.inspect_tree_collision(paths_collision)
        self.assertFalse(res_col["passed"])
        self.assertEqual(res_col["collision_count"], 1)

    # ---------------------------------------------------------
    # Pillar 2 Tests: Repo Topology, Submodules & Cross-Repo
    # ---------------------------------------------------------
    def test_05_submodule_tx_coordinator(self):
        coord = SubmoduleTransactionCoordinator()
        tx = coord.begin_atomic_commit(
            parent_repo="enterprise-monorepo",
            parent_sha="commit_parent_999",
            submodules={"vendor/core": "child_sha_111", "libs/crypto": "child_sha_222"}
        )
        self.assertTrue(tx["tx_id"].startswith("TX-SUB-"))
        self.assertEqual(tx["status"], "COMMITTED")

        token = coord.mint_ephemeral_oidc_token("runner_42", "https://github.com/corp/crypto.git")
        self.assertTrue(token["token"].startswith("os_sub_jit_"))

    def test_06_sat_merge_solver(self):
        # Compatible upgrade
        res = SATMergeSolver.resolve_dependency_conflict("serde", "1.0.100", "1.0.110", "1.0.115")
        self.assertEqual(res["resolved_version"], "1.0.115")
        self.assertTrue(res["formally_verified"])

        # Breaking major divergence
        res_break = SATMergeSolver.resolve_dependency_conflict("tokio", "0.2.0", "1.0.0", "0.3.0")
        self.assertFalse(res_break["formally_verified"])

        # 0.x compatible patch upgrade
        res_zero = SATMergeSolver.resolve_dependency_conflict("axum-core", "0.4.0", "0.4.1", "0.4.2")
        self.assertEqual(res_zero["resolved_version"], "0.4.2")
        self.assertTrue(res_zero["formally_verified"])

    def test_07_contract_hypergraph(self):
        hypergraph = ContractHypergraph()
        hypergraph.register_provider_schema("BillingService", {"charge_id": "string", "amount_cents": "int"})
        hypergraph.register_consumer_dependency("AnalyticsWorker", "BillingService", ["charge_id", "amount_cents"])

        # Backward-compatible addition
        comp = hypergraph.verify_proposed_schema_change("BillingService", {"charge_id": "string", "amount_cents": "int", "currency": "string"})
        self.assertTrue(comp["compatible"])

        # Breaking removal
        broken = hypergraph.verify_proposed_schema_change("BillingService", {"charge_id": "string"})
        self.assertFalse(broken["compatible"])
        self.assertEqual(broken["broken_count"], 1)

    def test_08_merkle_redaction_engine(self):
        secret_blob = b"SUPER_SECRET_PRODUCTION_DATABASE_PASSWORD"
        nullifier = MerkleRedactionEngine.generate_redaction_nullifier(secret_blob)
        self.assertTrue(nullifier["nullifier_proof"].startswith("NULLIFIER-ZK-"))

        valid = MerkleRedactionEngine.verify_nullifier(nullifier["original_sha256"], nullifier["nullifier_proof"])
        self.assertTrue(valid)

    # ---------------------------------------------------------
    # Pillar 3 Tests: CI/CD Runner Isolation & Kernel MMU
    # ---------------------------------------------------------
    def test_09_context_taint_engine(self):
        unsafe_workflow = """
        name: Untrusted PR
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.pull_request.title }}"
        """
        scan_unsafe = ActionContextTaintEngine.scan_workflow(unsafe_workflow)
        self.assertFalse(scan_unsafe["safe"])
        self.assertEqual(scan_unsafe["taint_findings_count"], 1)

        safe_workflow = """
        name: Safe PR
        on: pull_request
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - env:
                  TITLE: ${{ github.event.pull_request.title }}
                run: echo "$TITLE"
        """
        scan_safe = ActionContextTaintEngine.scan_workflow(safe_workflow)
        # Scan passes when inside env: mapping instead of run: execution context
        self.assertTrue(scan_safe["safe"])
        self.assertEqual(scan_safe["taint_findings_count"], 0)

    def test_10_cache_attestation(self):
        cache_engine = CacheAttestationEngine()
        payload = b"tar_gz_cached_cargo_target_directory"
        att = cache_engine.sign_cache_artifact("feature-123", "cache-cargo-key-1", payload)
        self.assertEqual(att["slsa_level"], "SLSA_BUILD_LEVEL_3")

        # Allowed restore by same branch
        verify_same = cache_engine.verify_cache_restore("feature-123", "cache-cargo-key-1", payload)
        self.assertTrue(verify_same["allowed"])

        # Blocked poisoned restore by foreign branch
        verify_foreign = cache_engine.verify_cache_restore("malicious-pr-99", "cache-cargo-key-1", payload)
        self.assertFalse(verify_foreign["allowed"])

    def test_11_wasm_compilation_server(self):
        server = WasmCompilationServer()
        dummy_wasm = b"\x00asm\x01\x00\x00\x00"
        server.load_module("eslint-wasm", dummy_wasm)
        res = server.execute_in_memory("eslint-wasm", "const x = 42;\nconsole.log(x);")
        self.assertTrue(res["zero_fork_syscalls"])
        self.assertEqual(res["module"], "eslint-wasm")

    def test_12_criu_preemption_manager(self):
        criu = CRIUPreemptionManager()
        criu.start_job("integration-test-job", priority=2, memory_mb=4096)
        criu.start_job("lint-job", priority=1, memory_mb=512)

        preempted = criu.preempt_for_hotfix("p0-security-hotfix", hotfix_priority=10)
        self.assertEqual(len(preempted), 2)

        resumed = criu.resume_job("integration-test-job")
        self.assertTrue(resumed)

    # ---------------------------------------------------------
    # Pillar 4 Tests: Supply Chain Provenance & Registry Integrity
    # ---------------------------------------------------------
    def test_13_slsa_provenance_engine(self):
        slsa = SLSAProvenanceEngine()
        binary = b"\x7fELF_COMPILED_RELEASE_BINARY"
        res = slsa.mint_slsa_envelope(
            package_name="@orderstream/mesh-core",
            version="1.0.0",
            git_commit_sha="a1b2c3d4e5f67890",
            runner_oidc_claims={"job_id": "999888", "repo": "OrderStream/orderstream-mesh"},
            compiled_binary_bytes=binary
        )
        self.assertTrue(res["verified"])
        self.assertTrue(slsa.verify_envelope(res["envelope"], res["signature"]))

    def test_14_merkle_timestamp_authority(self):
        ts_auth = MerkleTimestampAuthority()
        entry = ts_auth.timestamp_commit("commit_hash_7788", "ahmed@orderstream.io")
        self.assertEqual(entry["log_index"], 0)

        verify = ts_auth.verify_commit_in_rekor("commit_hash_7788")
        self.assertTrue(verify["valid"])
        self.assertTrue(verify["permanent_verified"])

    def test_15_micro_patch_synthesizer(self):
        patch = MicroPatchSynthesizer.slice_and_patch(
            abandoned_pkg="left-pad-abandoned",
            called_functions=["left_pad", "is_string"],
            vulnerable_func="left_pad",
            patch_replacement="def left_pad(s, n): return s.rjust(n)"
        )
        self.assertTrue(patch["severed_upstream"])
        self.assertEqual(patch["sliced_function_count"], 2)
        self.assertIn("rjust", patch["in_tree_shim"]["left_pad"])

    def test_16_smt_reachability_solver(self):
        solver = SMTReachabilitySolver()
        solver.register_call_edge("app_main", "handle_request")
        solver.register_call_edge("handle_request", "sanitize_input")
        # Vulnerable sink not linked to app_main
        res_unreachable = solver.is_sink_reachable("app_main", "cve_vulnerable_xml_parser")
        self.assertFalse(res_unreachable["static_path_exists"])
        self.assertEqual(res_unreachable["action"], "SAFE_NOISE_DISMISSED")

        # Now link vulnerable sink and simulate runtime call
        solver.register_call_edge("handle_request", "cve_vulnerable_xml_parser")
        solver.record_ebpf_runtime_call("cve_vulnerable_xml_parser")
        res_reachable = solver.is_sink_reachable("app_main", "cve_vulnerable_xml_parser")
        self.assertTrue(res_reachable["true_positive_risk"])
        self.assertEqual(res_reachable["action"], "BLOCK_PR_CRITICAL")

    # ---------------------------------------------------------
    # Pillar 5 Tests: GitOps & Enterprise Scale
    # ---------------------------------------------------------
    def test_17_gitops_lens_reconciler(self):
        reconciler = GitOpsLensReconciler()
        reconciler.set_git_state("k8s_cluster_replicas", 3)

        # Ingest emergency hotfix from AWS CloudTrail
        res = reconciler.ingest_out_of_band_event("AWS_CloudTrail", "k8s_cluster_replicas", 10)
        self.assertTrue(res["drift_detected"])
        self.assertEqual(res["reverse_pr"]["lens_resolution"], "ADOPT_LIVE_HOTFIX_INTO_GIT")

    def test_18_api_traffic_shaper(self):
        shaper = APITrafficShaper(capacity=2, refill_rate_per_sec=1.0)
        call_count = 0
        def dummy_query():
            nonlocal call_count
            call_count += 1
            return {"prs": 42}

        # First query hits source
        r1 = shaper.execute_throttled_query("get_prs", dummy_query)
        self.assertEqual(call_count, 1)

        # Repeated query coalesced
        r2 = shaper.execute_throttled_query("get_prs", dummy_query)
        self.assertTrue(r2["coalesced"])
        self.assertEqual(call_count, 1)

    def test_19_crdt_git_storage_engine(self):
        engine_us = CRDTGitStorageEngine(region="us-east-1")
        engine_eu = CRDTGitStorageEngine(region="eu-central-1")

        event = engine_us.push_speculative_commit("refs/heads/main", "commit_sha_us_1")
        self.assertTrue(event["sub_millisecond_ack"])

        # Merge in EU region
        engine_eu.merge_remote_crdt_state("us-east-1", "refs/heads/main", event["lamport_clock"], "commit_sha_us_1")
        self.assertEqual(engine_eu.local_refs["refs/heads/main"][1], "commit_sha_us_1")

    def test_20_semantic_blame_tracker(self):
        blame = SemanticASTBlameTracker()
        blame.register_symbol("calculate_yield", "fn calculate_yield(amount: u64) -> u64 { amount * 2 }", "alice", "sha_100")

        # Bob reformats code with spaces
        reformatted = "fn calculate_yield( amount: u64 ) -> u64 { \n  amount * 2 \n}"
        res = blame.blame_symbol("calculate_yield", reformatted, "bob", "sha_200")
        # Syntactic formatting ignored: Alice remains true blame author!
        self.assertEqual(res["author"], "alice")
        self.assertEqual(res["lineage"], "SYNTACTIC_REFORMAT_IGNORED")

    # ---------------------------------------------------------
    # Pillar 6 Tests: Socio-Technical & Review Horizons
    # ---------------------------------------------------------
    def test_21_dynamic_policy_evaluation_engine(self):
        # Normal high blast radius PR requires 2 reviews
        pol_high = DynamicContextPolicyEngine.evaluate_merge_policy(pr_changed_lines=500, is_p0_incident=False, approvers=["alice"])
        self.assertFalse(pol_high["allowed"])

        # P0 incident allows 1 approval
        pol_p0 = DynamicContextPolicyEngine.evaluate_merge_policy(pr_changed_lines=500, is_p0_incident=True, approvers=["alice"])
        self.assertTrue(pol_p0["allowed"])

        # Break-glass override
        pol_bg = DynamicContextPolicyEngine.evaluate_merge_policy(pr_changed_lines=1000, is_p0_incident=False, approvers=[], break_glass=True)
        self.assertTrue(pol_bg["allowed"])
        self.assertEqual(pol_bg["strategy"], "EPHEMERAL_BREAK_GLASS_OVERRIDE")

    def test_22_behavioral_fuzz_sandbox(self):
        old_spec = {"/api/v1/auth": {"return_type": "AuthToken"}}
        new_spec_identical = {"/api/v1/auth": {"return_type": "AuthToken"}}
        res_pass = BehavioralFuzzSandbox.fuzz_differential(old_spec, new_spec_identical)
        self.assertTrue(res_pass["safe_to_automerge"])
        self.assertTrue(res_pass["cryptographic_safety_certificate"].startswith("CERT-DIFF-FUZZ-"))

        new_spec_broken = {"/api/v1/auth": {"return_type": "StringSessionId"}}
        res_fail = BehavioralFuzzSandbox.fuzz_differential(old_spec, new_spec_broken)
        self.assertFalse(res_fail["safe_to_automerge"])

    def test_23_dynamic_state_diff_engine(self):
        risky_code = """
        def divide_balance(total, count):
            return total / 0
        def get_item(vec):
            return vec.unwrap()
        """
        trace = DynamicStateDiffEngine.generate_counterexample_trace(risky_code)
        self.assertTrue(trace["has_counterexamples"])
        self.assertEqual(len(trace["counterexamples"]), 2)

    def test_24_scip_symbol_indexer(self):
        indexer = SCIPSymbolIndexer()
        indexer.index_symbol("auth-service", "src/token.rs", "verify_jwt_token", "Function", 45)
        indexer.index_symbol("gateway-service", "src/proxy.rs", "verify_jwt_token", "CallSite", 112)

        results = indexer.query_symbol("verify_jwt_token")
        self.assertEqual(len(results), 2)
        search_ast = indexer.search_semantic_ast(["jwt"])
        self.assertEqual(len(search_ast), 2)

if __name__ == "__main__":
    unittest.main()

