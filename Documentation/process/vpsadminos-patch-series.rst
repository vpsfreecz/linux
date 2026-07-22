.. SPDX-License-Identifier: GPL-2.0

.. _vpsadminos_patch_series:

=========================================
vpsAdminOS downstream patch-series policy
=========================================

The vpsfree.cz fork maintains vpsAdminOS release branches as reviewed logical
patch series.  Their shipping history describes durable behavior, not the
chronological sequence of fixes made while developing it.

Follow these rules for every downstream release stack:

* One commit owns one coherent feature, new type of functionality, or distinct
  behavior change.  Fold feature-specific helpers, callers, tests,
  compatibility work, completions, and caused fixes into that owner.  Split
  mixed changes; keep an independent upstream or baseline fix separate when
  that is its true identity.  Do not combine unrelated work merely to reduce
  the commit count.
* Prefix every commit that carries genuine vpsAdminOS-owned functionality,
  ABI, product policy, or intentional behavior with the exact subject marker
  ``[vpsAdminOS]``.  This is a semantic ownership marker, not a blanket marker
  for every patch the distribution carries.  Pristine upstream backports,
  independent generic fixes, and separate support-only patches remain
  unmarked.
* Treat the first unversioned publication of a downstream logical patch as
  v1.  Advance ``vN`` for a real source, semantic, compatibility-port,
  folded-correction, or substantive-message revision.  A patch-identical
  transplant or publication-only Git object does not create a new version.
* Revised downstream patches carry a chronological development history that
  explains what changed at each real version.  A meaningful commit message
  explains the problem, before/after behavior, design and invariants,
  provenance, relevant constraints, and validation.
* Preserve truthful upstream subjects, authorship, messages, credits, and
  trailers.  Record adaptations explicitly and never invent a sign-off or
  other contributor attestation.
* Release history must not contain ``fixup!``, ``squash!``, WIP, temporary
  audit, duplicate-revision, or repair-tail commits.  Every retained boundary
  must remain reviewable and bisectable to the extent the kernel permits.
* Before promotion, review the complete downstream range directly,
  patch-by-patch and as a final tree, and run the appropriate exact-head
  product validation.  Keep exact refs, decisions, results, and remaining
  work only in the existing Markdown release tracker.  Do not create a review
  harness, schema, machine ledger, manifest, registry, generator, verifier,
  scheduler, evidence bundle, or parallel state system.  Release-specific
  excluded projects are selected explicitly by the review; they are not
  hard-coded into this general policy.
