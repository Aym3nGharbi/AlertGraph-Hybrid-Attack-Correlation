# Public V2 implementation

This repository publishes reusable source code and synthetic tests. It does not
publish the laboratory's sealed campaigns, annotations, raw Wazuh events, SSH
journals, Windows EVTX exports, execution receipts, credentials, trained models,
or datasets. Operational reports are deliberately kept outside this release.

## Available components

- Strict BootId UUID comparison and reversible meta-alert provenance checks.
- Process supervision that retains unresolved cleanup failures, plus a bounded
  concurrent scheduler and separate technical/execution receipts.
- Persistent SSH and sudo journal byte capture with cursor/BootId/hash checks.
- Separate original and 2.1 sudo adapters. The latter removes one ASCII syslog
  envelope separator, preserves all message whitespace, and retains exact
  journal/source equality and the original provenance predicates. It was a
  post-execution parser correction; independent prospective validation remains
  required. Campaign-specific replay scripts and private protocols are omitted.
- Experimental C1/C2 compression and conservative candidate-generation studies,
  kept separate from V1 and from operational deployment. Four raw evidence
  bundles are not claimed to be statistically independent.
- Experimental description TF-IDF with development-only vocabulary fitting and
  instrumentation-marker filtering. No ML V2 classifier is trained or released.
- Windows/Sysmon parent-child pilot tooling under `windows_process/`: controlled
  stdin gates, independent live-process birth observations, original event XML
  and binary EVTX subset export, SHA-256 verification, strict source-record
  matching, and comparison of C0/C1/C2/uncompressed with V2-0/V2-3.

## Public examples and private laboratory configuration

Addresses in the new example tooling use the RFC 5737 documentation range
`192.0.2.0/24`; account and agent names are fictitious. These publication copies
are intentionally distinct from the private lab defaults and frozen protocols.
The private original files remain untouched locally. No real campaign plan or
annotation revision can be reconstructed from this release.

Windows execution is preview-only by default. A real run additionally requires
an explicitly authorized isolated lab, a reviewed campaign reservation and
sealed source protocol, an accepted fresh clock audit, authenticated WinRM HTTPS,
and source/collector permissions. No service installation/start, NTP changes or
security-policy relaxation is performed automatically. The companion JSON is
only a synthetic reservation example, not an execution authorization or a
complete signed protocol. Never use the documentation addresses as real targets.

Sysmon Event ID 1 and ProcessGuid are used for process identity; Event ID 11
requires independent file-operation evidence and is not automatically attributed.
XML and Wazuh are copies of one event producer, not two independent proofs.
Unknown/ambiguous events are excluded and are never automatically negative.
Benign-benign pairs are never exported for ML V2 training.

The Windows native parent/child launch and EVTX export remain prospectively
unvalidated. A synthetic end-to-end test does not establish real attribution or
attack detection performance. No AP/F1/MCC or attack-graph quality is claimed for
a benign observability pilot. `training_ready: false` remains the project state.

## Local verification without private data

Install the existing project Python requirements, then run:

```powershell
python -m unittest discover -s lab/dataset_v2 -t . -q
```

Tests use synthetic temporary bundles, mocks and harmless local Python children;
they do not contact lab VMs or run attack scenarios. No embeddings or model
weights are downloaded. The publication checks are performed on this public
snapshot, not on the private lab data.

For a new Windows reservation, adapt `examples/windows-process-scenario.json`
to a separately authorized environment and use `prepare_campaign.py`. Construct
and review that environment's own source-hash protocol before any execution.
The CLI `python -m lab.dataset_v2.windows_process.run <campaign-directory>` is a
network-free preview only when a matching reservation/protocol is present.

V1 algorithms, models, mappings and historical scientific results are not changed
by this publication. Complete-campaign development/validation/final-test
separation, prospective freezing and strict supervision remain required.

Publication verification: **188 synthetic V2 tests passed** on the public
snapshot (18 November 2026). This is software validation, not a new laboratory
experiment or a claim of ML/generalization performance.
