"""
OrderStream Enterprise Engineering Mesh
Architected platform of 24 High-Performance Solvers across 6 Critical Pillars.
"""

from .pillar1 import MVCCIndexBTree, BitmapCommitGraph, FastCDCChunker, UnicodeCaseFoldingGate
from .pillar2 import SubmoduleTransactionCoordinator, SATMergeSolver, ContractHypergraph, MerkleRedactionEngine
from .pillar3 import ActionContextTaintEngine, CacheAttestationEngine, WasmCompilationServer, CRIUPreemptionManager
from .pillar4 import SLSAProvenanceEngine, MerkleTimestampAuthority, MicroPatchSynthesizer, SMTReachabilitySolver
from .pillar5 import GitOpsLensReconciler, APITrafficShaper, CRDTGitStorageEngine, SemanticASTBlameTracker
from .pillar6 import DynamicContextPolicyEngine, BehavioralFuzzSandbox, DynamicStateDiffEngine, SCIPSymbolIndexer

__version__ = "1.0.0"
__all__ = [
    # Pillar 1
    "MVCCIndexBTree",
    "BitmapCommitGraph",
    "FastCDCChunker",
    "UnicodeCaseFoldingGate",
    # Pillar 2
    "SubmoduleTransactionCoordinator",
    "SATMergeSolver",
    "ContractHypergraph",
    "MerkleRedactionEngine",
    # Pillar 3
    "ActionContextTaintEngine",
    "CacheAttestationEngine",
    "WasmCompilationServer",
    "CRIUPreemptionManager",
    # Pillar 4
    "SLSAProvenanceEngine",
    "MerkleTimestampAuthority",
    "MicroPatchSynthesizer",
    "SMTReachabilitySolver",
    # Pillar 5
    "GitOpsLensReconciler",
    "APITrafficShaper",
    "CRDTGitStorageEngine",
    "SemanticASTBlameTracker",
    # Pillar 6
    "DynamicContextPolicyEngine",
    "BehavioralFuzzSandbox",
    "DynamicStateDiffEngine",
    "SCIPSymbolIndexer",
]

