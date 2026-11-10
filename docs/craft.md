# Craft projects

The craft layer turns rea-python from a stateless analyzer into a headless project workflow:

```text
Study -> Build -> Check -> Refine -> Ready
```

It deliberately reuses the existing analysis engine and Evidence model. It does not embed a
model or a GUI.

## Project layout

```text
project/
  project.json              # project manifest
  investigation/
    brief.md                # instructions for the builder
    plan.json
    handoff.md
    evidence/ab/<id>.json
    unknowns/<id>.json
    findings/<id>.json
    hypotheses/<id>.json
    journal.jsonl
  capture/
    target.json             # website layout/screenshots or local triage
    screenshot-<width>.png
    page.html               # Deep mode only
  reference/
  app/                      # the new build
  checks/round-N/           # CheckResult JSON + artifacts
  inbox/                    # questions and approvals
  builds/round-N/           # prompt, builder metadata and usage
```

All project, check and builder files are intended to be versioned JSON with migration paths.
The current layer uses `project.json` version 1 and `CheckResult` JSON.

## Modes

- **clean_room** (craft default): study from screenshots/layout, user-provided reference and
  runtime observation. Do not read the original's code, files or page source.
- **deep**: use the full analysis engine, including source, decompilers and runtime inspection.

Clean room is a policy, not an OS sandbox. It does not protect against a coding agent's own
file/network permissions.

## Builders

The builder is an installed coding-agent CLI, not a rea-python-owned model loop. Detection tries
`aacode`, `opencode`, `claude`, `codex` and `dsh`, or an explicit command in
`REA_CRAFT_BUILDER_COMMAND`. A text-only OpenAI-compatible builder is selected with
`LLM_API_KEY`, `LLM_API_URL` and `LLM_MODEL_NAME` (or `--builder deepseek`); it receives layout
text only, never screenshots. `{prompt}` is replaced with the prompt; otherwise the prompt is
appended. The builder runs in `app/`, with `capture/` and `investigation/` available read-only.

## Checks

`CheckResult` is a typed record with `passed`, `similarity`, `claims`, `unknowns` and
`artifacts`. A project is Ready only when every latest check is good, every claim holds, no
unknown remains, and comparison meets `good_enough`.

Website visual checking is implemented and tested against local fixtures. Build checks support
npm, Cargo, Python and static sites. Game self-test consumes `app/self-test.json`. Java
archive/class inventory is implemented in pure Python; Java decompilation needs optional
Vineflower. Runtime-UI and generated-asset checks remain external or future work; they are
marked unverified rather than claimed as working. A small read-only dashboard is available with `rea project-serve`. Python check plugins can be
loaded from explicit `REA_PLUGIN_PATHS`; asset generation is a caller-supplied
`REA_ASSET_COMMAND` adapter. WASM plugins need an external wasm runtime and remain marked
unverified.

## Limits

- The builder must be installed and signed in by the user.
- External engine/game builds need their own tooling and licences.
- Never bypass DRM, logins or anti-cheat.
- Do not copy assets, logos or text from the original without permission.
