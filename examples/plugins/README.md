# Example Velora plugins

Two working plugins written against **Plugin SDK 2.0**. They are complete, not
sketches: drop the directory in and they run.

```bash
velora plugins load --dir examples/plugins
velora plugins list
velora scan --target <your-lab> --profile safe --i-am-authorized
```

Both are safe by construction:

* Every request goes through the scan's scope-gated client, so `ScopePolicy`,
  the request budget, the delay and the redirect policy all apply.
* Neither sends a state-changing verb — the SDK refuses to register a plugin that
  declares `PUT`, `PATCH`, `DELETE`, `CONNECT` or `TRACE`.
* Neither marks anything Confirmed. They emit evidence-backed observations; a human
  decides what they mean.

`cache_control.py` is `PASSIVE` — it reads what the scan already collected.
`wellknown_paths.py` is `ACTIVE_SAFE` — it issues extra plain reads, and shows how a
plugin declares and validates its own configuration.

See `docs/PLUGIN_DEVELOPMENT.md` for the full contract.
