# Attack graph

The attack graph is Velora's model of what it actually saw. Every node and every edge
carries four things: a confidence number, an epistemic state (`ValidationState`), the
evidence ids that support it, and the name of the component that asserted it. That is
what lets the graph tell a fact apart from a guess — an endpoint that returned 200 is not
the same kind of statement as a correlated chain between two findings.

Code: `velora/attack_graph/builder.py` (construction), `velora/attack_graph/paths.py`
(traversal and explanation), `velora/models/domain.py` (`AttackNode`, `AttackEdge`),
`velora/models/enums.py` (`ValidationState`). Tests: `tests/unit/test_attack_graph.py`.

## The headline caveat

**An `INFERRED` or `HYPOTHESIZED` path is a lead, never a demonstrated attack.** Velora
does not exploit anything, so it cannot demonstrate that a chain works. A path whose
weakest link is `INFERRED` or `HYPOTHESIZED` is a suggestion about where a human should
look. `GraphPath.is_hypothesis` returns `True` for both states, and `explain()` prints
"Validation required before this path is treated as real."

Even a fully `OBSERVED` path claims less than it might appear to. `explain()` ends such a
path with: "an evidenced path describes observed reachability. It does not by itself prove
exploitability or business impact."

## Validation states

`ValidationState` is the backbone of the evidence discipline. It is used by graph edges,
graph nodes, AI analyses, knowledge relationships and findings.

| State | Meaning in `velora/models/enums.py` | `is_fact` |
| --- | --- | --- |
| `OBSERVED` | Directly measured from a response. | yes |
| `INFERRED` | Derived deterministically from observations. | no |
| `HYPOTHESIZED` | Plausible but untested (AI / correlation). | no |
| `VALIDATED` | A human confirmed it. | yes |
| `UNKNOWN` | Insufficient information. | no |

`is_fact` is `True` only for `OBSERVED` and `VALIDATED`. The enum's own docstring states
the rule: "a statement must declare how it is known, and only a human can move something
to VALIDATED."

`INFERRED` is deliberately *not* a fact. A deterministic derivation from observations is
still a derivation — Velora did not see it happen.

`AttackEdge` also carries a legacy `hypothesis: bool`. It is not an independent field: the
builder sets it to `not state.is_fact` on every edge, and the model comment says it is
"kept for backward compatibility; derived from validation_status".

## Node kinds

These are the kinds `AttackGraphBuilder.build()` actually emits.

| Kind | Source | Confidence | Validation state |
| --- | --- | --- | --- |
| `Application` | The scan target itself. | `1.0` | `OBSERVED` |
| `Host` | A `Host` row from recon. | `1.0` | `OBSERVED` |
| `Port` | Target port, or 443/80 by scheme. | `1.0` | `OBSERVED` |
| `Endpoint` | An `Endpoint` row from the crawler. | `1.0` with a status code, else `0.6` | `OBSERVED` with a status code, else `INFERRED` |
| `Parameter` | First 10 parameters of an endpoint. | `1.0` | `OBSERVED` |
| `Technology` | A `Technology` row from fingerprinting. | the fingerprint engine's own confidence | `OBSERVED` at `>= 0.85`, else `INFERRED` |
| `Identity` | An `Identity` from the engagement. | `1.0` | `OBSERVED` |
| `Finding` | A `Finding` from this scan. | `finding.confidence.score` | `VALIDATED` if status is `Confirmed`, else `OBSERVED` |
| `Remediation` | Present only when the finding carries remediation text. | `1.0` | `INFERRED` |
| `Path` | One `Correlation`. Label is prefixed `[HYPOTHESIS]`. | `0.4` | `HYPOTHESIZED` |
| `Impact` | The consequence node for a correlation. | `0.35` | `HYPOTHESIZED` |

An endpoint with no status code is `INFERRED`, not `OBSERVED`: it was discovered as a link
but never successfully fetched, so its existence is a derivation from a page's markup
rather than something Velora measured.

A `Finding` node is `OBSERVED` because the *detection* was observed. It is not `VALIDATED`
until a human confirms the finding, at which point the builder picks that up from
`f.status`.

## Edge relations

`velora/attack_graph/builder.py` defines ten relation constants. Eight are emitted:

| Relation | Direction | Confidence | State | Asserted by |
| --- | --- | --- | --- | --- |
| `HOSTS` | Host → Application | `1.0` | `OBSERVED` | `recon` |
| `EXPOSES` | Host → Port | `1.0` | `OBSERVED` | `recon` |
| `CONTAINS` | Application → Endpoint | `1.0` | `OBSERVED` | `crawler` |
| `CONTAINS` | Endpoint → Parameter | `1.0` | `OBSERVED` | `crawler` |
| `USES` | Application → Technology | tech confidence | same as the tech node | `fingerprint` |
| `CAN_ACCESS` | Identity → Endpoint | `0.9` | `OBSERVED` | `authz.matrix` |
| `EXPOSES` | Endpoint (or Application) → Finding | `finding.confidence.score` | same as the finding node | the detecting check's id |
| `MITIGATED_BY` | Finding → Remediation | `0.8` | `INFERRED` | `remediation-catalog` |
| `LEADS_TO` | Finding → Path | `0.4` | `HYPOTHESIZED` | `correlation` |
| `AFFECTS` | Path → Impact | `0.35` | `HYPOTHESIZED` | `correlation` |

`REL_REQUIRES` (`"REQUIRES"`) and `REL_DEPENDS_ON` (`"DEPENDS_ON"`) are defined but no
code path emits them.

A `CAN_ACCESS` edge is written only for an authorization test whose `observed` value is
`GRANTED`, and only when both the identity node and the endpoint node exist. A denied or
inconclusive test produces no edge — the graph records access that was observed, not
access that was attempted.

## Edge direction, and why it matters

Edges follow the direction of the attack narrative:

```
Application --CONTAINS--> Endpoint --EXPOSES--> Finding --LEADS_TO--> Path --AFFECTS--> Impact
```

The builder's own comment on the `EXPOSES` edge records the history:

> Direction follows the attack narrative so paths are traversable:
> `Application -CONTAINS-> Endpoint -EXPOSES-> Finding -AFFECTS-> Impact`
> (1.x emitted `Finding -AFFECTS-> Endpoint`, which pointed against the flow and made
> path analysis impossible.)

This is not cosmetic. `AttackPathAnalyzer` builds its adjacency index keyed on
`edge.source_id` and walks forward only. With the 1.x direction, an endpoint had no
outgoing edge toward its finding, so a traversal starting at `Application` or `Endpoint`
reached the endpoint and stopped: no path from a reachable entry point ever arrived at a
`Finding` or an `Impact`. The *graph* looked complete and the *path analysis* returned
nothing useful. Reversing the edge makes reachability expressible: the question "what can
be reached from the front door, and what does that lead to" is a forward walk from an
entry kind, and every hop has to point the way an attacker would move.

The practical consequence for anyone reading the graph: an `EXPOSES` edge does not mean
the finding causes the endpoint. It means the endpoint is where that finding was observed,
written in the direction you would traverse it.

`MITIGATED_BY` runs Finding → Remediation. Since `Remediation` is not an impact kind, it
is a terminal branch rather than part of any reported path.

## Path analysis

`AttackPathAnalyzer.find_paths()` enumerates simple paths from an entry node to an impact
node.

```python
ENTRY_KINDS  = frozenset({"Application", "Endpoint", "Identity", "Host"})
IMPACT_KINDS = frozenset({"Impact", "Path", "Finding"})
```

Defaults: `max_depth=6`, `max_paths=50`, `min_length=2`. The `velora attack-map paths`
command overrides `max_paths` to `25`.

Bounds are enforced, not advisory. A node already on the current path is never revisited,
so cycles cannot hang the traversal; depth is capped per path and the total result count
is capped globally, so a dense graph cannot exhaust memory. Results are sorted strongest
and shortest first: `key=lambda p: (-p.confidence, p.length)`.

Because `min_length` is 2, a bare `Endpoint --EXPOSES--> Finding` hop is not reported on
its own; `Application --CONTAINS--> Endpoint --EXPOSES--> Finding` is.

### Confidence is the minimum edge confidence

```python
@property
def confidence(self) -> float:
    """A path is only as strong as its weakest edge."""
    if not self.edges:
        return 0.0
    return round(min(e.confidence for e in self.edges), 3)
```

Not a product, not an average. An average would let a long run of `1.0` structural edges
drown out one `0.35` hypothesis edge and make a speculative chain read as solid. A product
would decay with length, penalising a well-evidenced long path for being long. The minimum
answers the only question that matters for triage: how good is the worst thing this claim
rests on. A path containing a `0.35` correlation edge scores `0.35`, however many observed
hops surround it.

### Status is the weakest link

```python
@property
def validation_status(self) -> ValidationState:
    """The weakest epistemic state along the path governs the whole path."""
    if not self.edges:
        return ValidationState.UNKNOWN
    return min((e.validation_status for e in self.edges),
               key=lambda s: _STATE_RANK.get(s, 0))
```

Ranking, highest to lowest: `VALIDATED` 4, `OBSERVED` 3, `INFERRED` 2, `HYPOTHESIZED` 1,
`UNKNOWN` 0. One `HYPOTHESIZED` edge makes the whole path a hypothesis, and
`is_hypothesis` is `not validation_status.is_fact`, so an `INFERRED` path is a hypothesis
too. An empty path is `UNKNOWN` with confidence `0.0` — no edges means no claim, not a
safe claim.

`GraphPath.evidence_ids` collects the evidence ids of every edge in order, deduplicated,
so a path can be traced back to the stored observations.

### `render()`

One line per path, used by `velora attack-map paths`:

```
[HYPOTHESIS] Application:lab.local -> Endpoint:/admin -> Finding:weak authz
    confidence=0.40 status=HYPOTHESIZED evidence=2 item(s)
```

The marker is `HYPOTHESIS` or `EVIDENCED`, derived from `is_hypothesis`. Node labels are
truncated to 40 characters.

### `explain()`

`AttackPathAnalyzer.explain(path)` narrates one path without speculating. It opens with
one of two headers:

- hypothesis: `This path is a HYPOTHESIS: at least one step is not directly evidenced.`
- evidenced: `Every step in this path is backed by a direct observation.`

Then one numbered block per edge, marked `[OBSERVED ]` when `edge.validation_status.is_fact`
and `[ASSERTED ]` otherwise, with the relation, both node kinds and labels, then the edge's
confidence, state, asserting component, and up to three evidence ids.

It closes with the weakest-link confidence, the weakest-link status, and one of:

- hypothesis: `Validation required before this path is treated as real.`
- evidenced: `Note: an evidenced path describes observed reachability. It does not by itself prove exploitability or business impact.`

The second sentence is the point of the whole design. Velora reaches its strongest
possible verdict — every hop measured — and still refuses to call it exploitable, because
it never tried to exploit it. `tests/unit/test_attack_graph.py` asserts both strings:
`test_explain_labels_observed_and_asserted_steps` checks that a hypothesis path prints
`OBSERVED`, `ASSERTED`, `HYPOTHESIS` and `Validation required`, and
`test_explain_of_evidenced_path_still_disclaims_exploitability` checks that an evidenced
path still prints `does not by itself prove exploitability`.

### `summary()`

`AttackPathAnalyzer.summary()` returns node and edge totals, `nodes_by_kind`,
`edges_by_relation`, `edges_by_validation_status`, and `hypothesis_edges` — the count of
edges where `not edge.validation_status.is_fact`.

## CLI

All three forms read stored nodes and edges for a scan; none of them sends a request.

```
velora attack-map --scan <scan-id>
velora attack-map paths   --scan <scan-id> [--max-depth N] [--max-paths N] [--evidenced-only] [--json]
velora attack-map explain --scan <scan-id> [--index N] [--max-depth N]
```

| Command | Flag | Type | Default | Notes |
| --- | --- | --- | --- | --- |
| `attack-map` | `--scan` | text | — | Required when no subcommand is given. |
| `attack-map paths` | `--scan` | text | — | Required. |
| | `--max-depth` | integer | `6` | |
| | `--max-paths` | integer | `25` | |
| | `--evidenced-only` | flag | off | Hides hypothesis paths. |
| | `--json` | flag | off | Emits `GraphPath.to_dict()` per path. |
| `attack-map explain` | `--scan` | text | — | Required. |
| | `--index` | integer | `1` | 1-based path index. |
| | `--max-depth` | integer | `6` | |

`velora attack-map --scan <id>` with no subcommand prints the summary: nodes by kind,
edges by relation, edges by validation status, and — when any hypothesis edge exists — a
warning naming the count and stating that they require manual validation.

`attack-map paths` prints each path's `render()` output and finishes with a line counting
how many of the returned paths are hypotheses requiring validation. `--evidenced-only`
filters *after* enumeration, so the count of paths shown can be smaller than `--max-paths`.

`attack-map explain` enumerates with `max_paths=max(index, 25)` and then explains the
path at `--index`. An out-of-range index is an error naming the valid range, rather than
a silently clamped result.

## Discrepancies to be aware of

- `velora/attack_graph/builder.py`'s module docstring lists `Evidence` and `Control` as
  node kinds. Neither is emitted anywhere in `build()`.
- The same docstring lists `REDIRECTS` as an edge kind. There is no `REL_REDIRECTS`
  constant and no code emits that relation.
- `AttackNode.kind`'s inline comment in `velora/models/domain.py` lists a different
  vocabulary again (`Domain`, `API`, `Form`, `Cookie`, `Privilege`, `Data`), none of which
  the builder produces. The `kind` field is a free-form `str`, so nothing enforces either
  list; the table above is what the code emits.
