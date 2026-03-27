# Neo4j Requirement Types

## Requirement Satisfaction Semantics

| Type | Semantics | Examples |
|------|-----------|---------|
| **Access** | Satisfy **any one** — how you get in | `authentication/plaintext`, `session/windows/meterpreter`, `session/smb` |
| **Information** | Satisfy **all** — data the module needs | `domain_sid`, `computer_account`, `machine_key`, `target_dc_hostname` |
| **Trigger** | Satisfy **any one** — event that kicks it off | `coercion/smb`, `coercion` |

## Design Rationale

- **Access** requirements represent interchangeable methods of authenticating or connecting to a target. A module that accepts `authentication/plaintext`, `authentication/hash/ntlm`, or `session/windows/meterpreter` only needs *any one* of those to run.
- **Information** requirements represent specific data prerequisites that a module needs. Unlike access methods, these are not interchangeable — if a module needs both a `domain_sid` and a `computer_account`, it needs *all* of them.
- **Trigger** requirements represent events or conditions that enable a module. A capture server that accepts `coercion` or `coercion/smb` only needs one trigger to fire.

Credentials stay under Access (not Information) because they are interchangeable access methods. A domain SID is fundamentally different — it's not an alternative to a password, it's an additional prerequisite. This distinction maps cleanly to the any-one vs must-have-all split.

## PRODUCES Relationship Weights

PRODUCES relationships carry a `weight` property that indicates how reliably a module produces a specific output. Weights are configured inline in `transforms.yml` using named levels:

| Level | Value | Meaning |
|-------|-------|---------|
| `highest` | `2.0` | The canonical/best way to produce this |
| `high` | `1.0` | Reliably produces this |
| `normal` | `0.0` | No opinion (default, same as omitting) |
| `low` | `-1.0` | Less reliable for this |
| `lowest` | `-2.0` | Unlikely/rare outcome |

Pathfinding sorts by shortest chain length first, then by highest total weight as a tiebreaker among paths of equal length.

Example in `transforms.yml`:

```yaml
auxiliary/admin/kerberos/get_ticket:
  add:
    authentication_out:
      - kerberos: highest   # the go-to module for kerberos tickets
```

Entries without a weight level are treated as `normal` (weight `0.0`).

## Query Pattern

```cypher
// Find modules where you can satisfy ALL their requirements
MATCH (target:Module)-[:REQUIRES]->(req:Requirement)
WITH target, collect(req) AS all_reqs,
     [r IN collect(req) WHERE r:Access] AS access_reqs,
     [r IN collect(req) WHERE r:Information] AS info_reqs,
     [r IN collect(req) WHERE r:Trigger] AS trigger_reqs
// For Access/Trigger: do I have at least ONE?
// For Information: do I have ALL of them?
```
