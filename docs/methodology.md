# Methodology
Topology: provider->customer links 100>200, 100>300, 100>400, 200>500, 200>600, 300>700, 400>800, 600>800 (guide section 1).
Policy: local-pref customer 200 / peer 150 / provider 100; peer/provider routes exported only to customers.
Ranking: local origin, local-pref, shortest AS path, oldest route, lowest neighbour router-id.
Run: converge baseline with the victim originating; check all 6 measured ASes reach AS65700 (else baseline unhealthy);
then inject the attack and re-converge; probe 10.10.0.1:8080 from each measured AS by hop-by-hop longest-prefix forwarding.
Path convention: AS path listed nearest-first; last AS = claimed origin. Type-1 advertised path = [65800, 65700].
ROV: reject Invalid; Valid and NotFound accepted (configurable). Default ROA 10.10.0.0/24 AS65700 max 24.
Path-end: for a route with registered origin V, path must be [V] or path[-2] in registry(V) (AS65700 -> AS65300).
Aggregation: all C(6,k) adopter sets by default (exact means/sd); sampling or ordered/explicit sets are labelled.
Objective -> implementation: Type-0 vs Type-1 (attack_comparison), incremental ROV (rov_adoption), placement (placement),
path-end (path_end_adoption), reproducibility (store, versions.txt, run_all.py), sub-prefix (subprefix).
