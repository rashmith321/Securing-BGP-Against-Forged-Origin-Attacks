# Limitations
- Simulation, not a real Internet or production BGP testbed; Mininet/FRR/Routinator validation is future work.
- 8 ASes, 6 measured: D moves in steps of 16.7 points; results are topology- and policy-specific.
- Route-age tie-break mirrors FRR behaviour but was not validated against a real FRR run.
- Path-end is a simplified ASPA-inspired model, not standards-compliant ASPA.
- Some adopter sets leave a stub AS with no route (filtered update replaces the earlier valid route); reported as unreachable, not hidden.
- Not generalisable to the whole Internet without further experiments.
