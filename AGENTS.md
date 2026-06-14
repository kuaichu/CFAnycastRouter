# CF Anycast Router — AI Context

This is a Go local-agent project for continuously selecting the best Cloudflare Anycast ingress from the user's real network.

Important behavior:

- Candidates come from three local-learning pools: Seed Pool, Learned Pool, and Hot Pool.
- Seed IPs/CIDRs are expanded into sampled `/24` targets; never scan a whole Cloudflare range exhaustively.
- Learned segments are promoted when preferred POP probability passes the configured threshold.
- Hot IPs are stable low-score members of learned or seed segments and should get priority in selection.
- Scores include RTT, jitter, loss, spike rate, POP penalty, drift penalty, and hijack penalty.
- POP is detected through Cloudflare `/cdn-cgi/trace` using the configured `trace_host`.
- POP history is persisted in `data/state.json`; Asian POPs drifting to US/EU should be penalized and temporarily quarantined.
- Switching must be conservative: improvement threshold plus stable rounds, with fast switch only when the current route degrades badly.
- Outputs are rendered files under `out/` by default; do not introduce secrets into `config.yaml`.
