# Agent-surface benchmarks

The goal is to compare context cost and task efficiency, not just raw analyzer
features. The article comparison uses four target families and repeated runs.

## Surface measurement

```bash
python benchmarks/measure_schema.py
python benchmarks/measure_schema.py --json
```

This measures each MCP toolset with `REA_MCP_CLIENT=minimal`, plus the bundled
`skill.md`, using `tiktoken` cl100k when available and a bytes/4 fallback.

## Task benchmark

```bash
python benchmarks/run_task_benchmark.py --target native=/bin/ls --json
python benchmarks/run_task_benchmark.py --tasks benchmarks/tasks.example.json --target android=/path/app.apk
```

The task runner measures the command sequence a skill would prescribe: turns,
wall time, output tokens, exit codes, and whether required facts appear. It does
not call an LLM, so it is reproducible in CI and safe to run locally.

## Agent task suite

Use four task families, three runs each, and record:

- wall-clock seconds
- input/output tokens (client-reported)
- tool calls and turns
- success score (facts found / required facts)
- cost
- Evidence limitations or false claims

Suggested tasks:

1. APK: package identity, permissions, signing certificate, one suspicious class.
2. Electron/ASAR: module graph, IPC boundary, one storage-to-network flow.
3. Native binary: format, imports/exports, one function reached from a string xref.
4. Managed assembly: type/member inventory, one IL method, one P/Invoke boundary.

Compare these modes:

- `skill only` (CLI)
- `core` MCP
- `native`/`web`/`android`/`managed` domain MCP
- `full` MCP
- `full --available-only`

Do not accept a token reduction that loses required facts or hides limitations.
