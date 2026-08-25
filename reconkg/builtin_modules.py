"""Built-in modules: the shipped stages, with declared metadata and options.

These wrap the concrete stages in `stages.py` rather than reimplementing
them, so behaviour stays covered by the existing engine tests while gaining a
module identity, references, and a typed option datastore.

Every module here is read-only with respect to targets. `run()` consumes
evidence someone else collected.
"""

from __future__ import annotations

from datetime import date

from .modules import (ModuleInfo, Option, OptType, Rank, RefType, Reference,
                      ReconModule, registry)
from .stages import (BannerStage, ConnectSweepStage, DeepProbeStage,
                     HttpAppStage, OperatorStage, Outcome, PortSweepStage,
                     StageResult)

AUTHOR = "reconkg built-ins"

CONFIDENCE_NOTE = ("Declared confidence is advisory. The effective value is "
                   "clamped by the operator's SourceRegistry ceiling for the "
                   "tool; a module cannot raise its own credibility.")


def _rhost_option() -> Option:
    """The one option an operator actually sets by hand.

    When a module runs inside a pipeline the engine supplies the address
    directly, so this is informational there; the console requires it before
    `run` because there is nothing else to scope the work to.
    """
    return Option("RHOST", OptType.ADDRESS, None, True,
                  "Target address (IPv4/IPv6/hostname) to scope evidence to")


def _confidence_option(default: float, description: str) -> Option:
    return Option("CONFIDENCE", OptType.FLOAT, default, False, description,
                  minimum=0.0, maximum=1.0, advanced=True)


def _timeout_option(default: float) -> Option:
    return Option("TIMEOUT", OptType.FLOAT, default, False,
                  "Seconds before the stage is abandoned and fallback runs",
                  minimum=0.01, maximum=3600.0, advanced=True)


class _OptionBackedStage(ReconModule):
    """Applies TIMEOUT / DECAY options onto the DiscoveryStage attributes."""

    def __init__(self, **overrides) -> None:
        super().__init__(**overrides)
        timeout = self.opt("TIMEOUT")
        if timeout is not None:
            self.timeout_s = timeout
        decay = self.opt("DECAY")
        if decay is not None:
            self.decay_factor = decay


@registry.register
class SynSweepModule(_OptionBackedStage, PortSweepStage):
    meta = ModuleInfo(
        fullname="recon/discovery/syn_sweep",
        name="TCP SYN reachability sweep (evidence import)",
        description=(
            "Imports parsed SYN-sweep results and asserts port reachability. "
            "Reachability is the one thing a sweep is genuinely authoritative "
            "about, which is why this module carries a high rank while saying "
            "nothing about what is actually listening."),
        authors=(AUTHOR,),
        rank=Rank.GREAT,
        platforms=("agnostic",),
        references=(Reference(RefType.URL, "https://nmap.org/book/synscan.html"),
                    Reference(RefType.ATTACK, "T1046")),
        notes=("Half-open sweeps are frequently dropped by stateful filters; "
               "recon/discovery/connect_sweep is the registered fallback.",
               CONFIDENCE_NOTE),
    )
    option_spec = (
        _rhost_option(),
        _timeout_option(8.0),
        Option("DECAY", OptType.FLOAT, 0.6, False,
               "Confidence multiplier applied to in-scope fingerprints on "
               "failure", minimum=0.01, maximum=1.0, advanced=True),
        _confidence_option(0.85, "Default confidence for imported port states"),
    )


@registry.register
class ConnectSweepModule(_OptionBackedStage, ConnectSweepStage):
    meta = ModuleInfo(
        fullname="recon/discovery/connect_sweep",
        name="TCP full-connect reachability sweep (evidence import)",
        description=(
            "Fallback reachability import. Completes the handshake, so it "
            "survives paths that silently drop half-open probes, at the cost "
            "of being slower and far noisier in target logs."),
        authors=(AUTHOR,),
        rank=Rank.GREAT,
        platforms=("agnostic",),
        references=(Reference(RefType.ATTACK, "T1046"),),
        notes=("Completed connections are logged by most services. Expect to "
               "appear in the target's logs.", CONFIDENCE_NOTE),
    )
    option_spec = (
        _rhost_option(),
        _timeout_option(20.0),
        Option("DECAY", OptType.FLOAT, 0.6, False,
               "Confidence multiplier applied on failure",
               minimum=0.01, maximum=1.0, advanced=True),
        _confidence_option(0.85, "Default confidence for imported port states"),
    )


@registry.register
class BannerProbeModule(_OptionBackedStage, BannerStage):
    meta = ModuleInfo(
        fullname="recon/fingerprint/banner_probe",
        name="Service banner identification (evidence import)",
        description=(
            "Imports banner-grab output into services and version "
            "fingerprints. Banners are self-reported and routinely truncated, "
            "spoofed, or backported -- an entry that names a product without "
            "a usable version is marked ambiguous, which downgrades the "
            "fingerprint and routes the pipeline to a deeper technique rather "
            "than recording a guess as fact."),
        authors=(AUTHOR,),
        rank=Rank.NORMAL,
        platforms=("agnostic",),
        references=(Reference(RefType.URL,
                              "https://nmap.org/book/vscan.html"),
                    Reference(RefType.ATTACK, "T1046")),
        notes=("Distribution backports break version-to-CVE inference: RHEL "
               "ships patched 2.4.6 that a naive matcher flags for a decade "
               "of CVEs. Corroborate before believing a banner version.",
               CONFIDENCE_NOTE),
    )
    option_spec = (
        _rhost_option(),
        _timeout_option(12.0),
        Option("DECAY", OptType.FLOAT, 0.5, False,
               "Confidence multiplier applied to ambiguous fingerprints",
               minimum=0.01, maximum=1.0, advanced=True),
        _confidence_option(0.6, "Default confidence for imported fingerprints"),
    )


@registry.register
class DeepProbeModule(_OptionBackedStage, DeepProbeStage):
    meta = ModuleInfo(
        fullname="recon/fingerprint/deep_probe",
        name="Protocol-specific deep identification (evidence import)",
        description=(
            "Fallback identification for services a banner grab could not "
            "resolve. Sends protocol-aware probes rather than reading "
            "whatever the service volunteers, so it usually pins an exact "
            "version -- at the cost of a much heavier, more detectable "
            "interaction."),
        authors=(AUTHOR,),
        rank=Rank.GOOD,
        platforms=("agnostic",),
        references=(Reference(RefType.URL,
                              "https://nmap.org/book/vscan-technique.html"),),
        notes=("Runs only when the primary probe returned ambiguous or "
               "failed.", CONFIDENCE_NOTE),
    )
    option_spec = (
        _rhost_option(),
        _timeout_option(30.0),
        Option("DECAY", OptType.FLOAT, 0.5, False,
               "Confidence multiplier applied on failure",
               minimum=0.01, maximum=1.0, advanced=True),
        _confidence_option(0.88, "Default confidence for imported fingerprints"),
    )


@registry.register
class HttpAppModule(_OptionBackedStage, HttpAppStage):
    meta = ModuleInfo(
        fullname="recon/http/app_fingerprint",
        name="HTTP application fingerprinting (evidence import)",
        description=(
            "Imports web-layer fingerprints for ports already identified as "
            "speaking HTTP. Valuable mainly as an independent second opinion "
            "on the server version -- and only if it was submitted by a "
            "different principal, since corroboration is measured on the "
            "submitter, not the tool label."),
        authors=(AUTHOR,),
        rank=Rank.GOOD,
        platforms=("agnostic",),
        references=(Reference(RefType.URL,
                              "https://github.com/urbanadventurer/WhatWeb"),
                    Reference(RefType.ATTACK, "T1592.002")),
        notes=("Skips cleanly when no HTTP service is known -- a skipped "
               "precondition is not a failure and does not trigger fallback.",
               CONFIDENCE_NOTE),
    )
    option_spec = (
        _rhost_option(),
        _timeout_option(15.0),
        Option("CONFIDENCE", OptType.FLOAT, 0.7, False,
               "Default confidence for imported app fingerprints",
               minimum=0.0, maximum=1.0, advanced=True),
    )


@registry.register
class OperatorEvidenceModule(_OptionBackedStage, OperatorStage):
    meta = ModuleInfo(
        fullname="recon/operator/observed",
        name="Operator observation (evidence import)",
        description=(
            "Imports what a human read off the target: a version in a page "
            "footer, a login banner, an About box. The only source in the "
            "registry with a 1.0 ceiling, and the only one that can answer "
            "an 'uncorroborated' gap -- corroboration is measured on the "
            "submitting principal, and every automated stage submits as the "
            "same one."),
        authors=(AUTHOR,),
        rank=Rank.EXCELLENT,
        platforms=("agnostic",),
        references=(Reference(RefType.ATTACK, "T1592.002"),),
        notes=("Runs last so a human's reading lands on top of what the "
               "tools inferred rather than under it.",
               "Never reports AMBIGUOUS: one version somebody is sure of is "
               "not evidence against a fingerprint on another port.",
               CONFIDENCE_NOTE),
    )
    option_spec = (
        _rhost_option(),
        _timeout_option(5.0),
        _confidence_option(1.0, "Default confidence for operator claims"),
    )


BUILTIN_MODULES = (
    SynSweepModule, ConnectSweepModule, BannerProbeModule,
    DeepProbeModule, HttpAppModule, OperatorEvidenceModule,
)


def module_pipeline():
    """The default pipeline, expressed in modules rather than raw stages.

    Kept in step with `engine.default_pipeline()` by hand, which is a seam
    worth naming: these are two spellings of one pipeline, `app.py` runs this
    one and `demo.py` runs the other, and a stage added to only one of them
    is a feature that works everywhere except the web UI. `test_wiring.py`
    asserts they hold the same stages for exactly that reason.
    """
    from .engine import StageSlot
    return [
        StageSlot(SynSweepModule(), [ConnectSweepModule()],
                  label="port-discovery"),
        StageSlot(BannerProbeModule(), [DeepProbeModule()], label="service-id"),
        StageSlot(HttpAppModule(), [], label="web-layer"),
        StageSlot(OperatorEvidenceModule(), [], label="operator-evidence"),
    ]
