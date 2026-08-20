"""reconkg -- asset knowledge graph and vulnerability-lead coordinator.

Read-only with respect to targets: this package correlates evidence that other
tools produced. It opens no connections to hosts under analysis and contains
no exploitation or payload-delivery code.
"""

from .engine import DiscoveryEngine, ScanReport, StageSlot, default_pipeline
from .auth import Authenticator, load_principals, validate_address
from .events import ConnectionManager
from .handoff import build_handoff, render_handoff
from .modules import (ModuleInfo, ModuleRegistry, Option, OptType, Rank,
                      ReconModule, RefType, Reference, registry)
from .planner import Gap, GapPlanner, Recommendation, render_plan
from .models import (ExploitMaturity, Fingerprint, Host, Port, PortState,
                     Provenance, Service, VulnLead)
from .stages import (BannerStage, ConnectSweepStage, DeepProbeStage,
                     DiscoveryStage, EvidenceSource, HttpAppStage, Outcome,
                     PortSweepStage, StageResult)
from .sources import SourceRegistry, SourceProfile, default_registry
from .store import ChangeEvent, EventKind, TargetStore
from .vulnref import (DEFAULT_REFERENCE, CorrelationConfig, LedgerRow,
                      VulnEntry, compare_versions, parse_version,
                      version_satisfies)

__version__ = "0.3.0"

__all__ = [
    "DiscoveryEngine", "ScanReport", "StageSlot", "default_pipeline",
    "ConnectionManager", "TargetStore", "ChangeEvent", "EventKind",
    "EvidenceSource", "DiscoveryStage", "StageResult", "Outcome",
    "PortSweepStage", "ConnectSweepStage", "BannerStage", "DeepProbeStage",
    "HttpAppStage", "Host", "Port", "Service", "Fingerprint", "VulnLead",
    "Provenance", "PortState", "ExploitMaturity", "VulnEntry",
    "CorrelationConfig", "LedgerRow", "DEFAULT_REFERENCE", "parse_version",
    "compare_versions", "version_satisfies", "SourceRegistry", "SourceProfile",
    "default_registry", "Authenticator", "load_principals", "validate_address",
    "ModuleInfo", "ModuleRegistry", "Option", "OptType", "Rank", "ReconModule",
    "RefType", "Reference", "registry", "Gap", "GapPlanner", "Recommendation",
    "render_plan", "build_handoff", "render_handoff",
]
