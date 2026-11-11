// SPDX-License-Identifier: MIT
// Original teaching graph. Not OGVKG and not the paper experiment graph.
MERGE (system:Domain:OGVulExample {name: 'System'})
MERGE (protocol:Domain:OGVulExample {name: 'Protocol'})
MERGE (bounds:CWE:OGVulExample {id: 'CWE-119'})
SET bounds.name = 'Memory boundary control'
MERGE (write:CWE:OGVulExample {id: 'CWE-787'})
SET write.name = 'Write outside destination capacity',
    write.verification_contract = 'Locate a dominating destination-capacity check before the copy. A null check alone does not bound the copy length.'
MERGE (release:CWE:OGVulExample {id: 'CWE-415'})
SET release.name = 'Repeated release of one heap allocation',
    release.verification_contract = 'Follow each branch and count releases of the same pointer. A return after a release prevents later cleanup on that path.'
MERGE (write)-[:CHILD_OF]->(bounds)
WITH system, protocol, write, release
UNWIND [
  {name: 'TelemetryFrame', kind: 'buffer'},
  {name: 'receive_telemetry', kind: 'buffer'},
  {name: 'payload', kind: 'buffer'},
  {name: 'telemetry', kind: 'buffer'},
  {name: 'buffer', kind: 'buffer'},
  {name: 'memcpy', kind: 'buffer'},
  {name: 'ValveState', kind: 'release'},
  {name: 'reset_valve_cache', kind: 'release'},
  {name: 'heap allocation', kind: 'release'},
  {name: 'memory management', kind: 'release'},
  {name: 'free', kind: 'release'}
] AS row
MERGE (entity:Entity:OGL_Node:OGVulExample {name: row.name})
MERGE (entity)-[:BELONGS_TO]->(system)
MERGE (entity)-[:BELONGS_TO]->(protocol)
FOREACH (_ IN CASE WHEN row.kind = 'buffer' THEN [1] ELSE [] END |
  MERGE (entity)-[risk:POTENTIAL_WEAKNESS]->(write)
  SET risk.reason = 'An externally supplied copy length may exceed the fixed destination buffer capacity. Verify the actual source-code length checks.'
)
FOREACH (_ IN CASE WHEN row.kind = 'release' THEN [1] ELSE [] END |
  MERGE (entity)-[risk:POTENTIAL_WEAKNESS]->(release)
  SET risk.reason = 'Multiple cleanup paths may release one heap allocation more than once. Verify ownership and control-flow exits in the source.'
)
RETURN count(entity) AS example_entities
