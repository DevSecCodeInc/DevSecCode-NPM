# Sprints

As of 2026-10-13, new sprints for this repository open in the shared workspace sprint set (dsc/docs/sprints/, outside this repository). This folder keeps the history.

NPM-specific work periods live here. Shared cross-product sprints remain in the
workspace's `docs/sprints/`; this directory does not close or supersede them.
A sprint opens and closes when Matt chooses, rather than on a fixed weekly
schedule. The current NPM sprint is the newest `SPRINT-YYYY-MM-DD.md` whose
Retrospective reads "Filled in when the sprint closes."

Tracks are Business (product boundaries and acceptance) and Engineering
(implementation and verification), each with Must and Stretch lists.
Sprint records schedule work; decisions belong in the
[migration plan](../DevSecCode-NPM%20Core%20Migration%20Plan.md), the
[refresh spec](../specs/npm-public-starter-refresh.md), and the
[release runbook](../npm-artifact-v2-release-runbook.md).

Each task has an id, owner, owning-document/workstream link, dependencies, and
a verifiable Done when. Engineering tasks list Touches, including shared files
and resources. Number each track in dependency order across Must and Stretch;
freeze ids after the first status note. New prerequisites become nested sub-tasks.

Append dated Status notes to task bullets. Tick and strike through completed
plan text, leaving the dated Done note outside the strike. Record unfinished
scope explicitly in Carry-over; never silently drop tasks. Close only when Matt
requests it, with a factual retrospective and actual close date.

Parallel waves require independent dependencies, disjoint Touches, and separate
acceptance outputs. Include merge order; unknown footprints remain serial.
Launch agents only when asked, one per task in its own worktree. They stay in
their Touches and return progress notes without editing the sprint record.

Core owns artifact production and signing. NPM accepts only signed immutable
public/starter inputs. Preserve unrelated changes and follow repository checks.
No sprint authorizes Git pushes, publication, external job dispatch, or monitoring.
Cross-repository tasks record each implementation commit separately; do not imply
the NPM sprint and Core implementation were committed atomically.
