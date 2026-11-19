# Re-recording the demo

The demo GIF is generated from `docs/demo.tape` using [VHS](https://github.com/charmbracelet/vhs).

## Prerequisites

Install VHS:

```bash
# macOS (Homebrew)
brew install vhs

# Linux (package manager or Go)
go install github.com/charmbracelet/vhs@latest

# Windows (Scoop)
scoop install vhs
```

## Record

```bash
vhs docs/demo.tape
```

This runs `agentbox demo` in an isolated terminal and outputs `docs/demo.gif`.

## Notes

- The tape executes only `agentbox demo`, which operates inside a clean temporary directory and deletes it upon completion. No personal paths, local usernames, or environment secrets appear in the recording.
- If you need to adjust timing (the demo completes in approximately 20–25 seconds), modify the `Sleep 25s` line in `docs/demo.tape`.
- Commit `docs/demo.tape` and `docs/RECORDING.md` to version control. The generated binary asset `docs/demo.gif` is ignored via `.gitignore` to keep repository size lean.
