# Contributing to agentbox

Thanks for helping. agentbox is a security-flavored project: its value is that its logs can be trusted. That shapes a few rules below, so please read them before opening a PR.

## Before you start

1. **Find or open an issue.** Comment that you want to take it and wait to be assigned. This avoids two people doing the same work.
2. **Say what you can't do.** If part of an issue needs something you don't have (for example an API key or Docker), say so in the issue and propose a split. Don't leave checklist items silently undone.
3. **Ask before large changes.** If you think something outside the issue needs changing, open a separate issue or ask in the thread first.

## Setup

~~~bash
git clone https://github.com/Agentboxx-dev/Agentboxx.git
cd Agentboxx
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
~~~

Docker is optional. The Docker test is skipped when Docker is unavailable.

## Making a change

- **Branch from `main`**, one branch per issue: `git checkout -b fix-short-description`.
- **Keep one purpose per PR.** Platform support, refactors and unrelated fixes belong in their own PR, even if small. A reviewer should be able to say what the PR is for in one sentence.
- **Use small, focused commits** with clear titles, such as `fix: refuse to append to an existing log`.

### Commit messages

- Describe the change, not a checklist position. Don't write titles like `Req #15-17`.
- **Don't write `#` followed by a number unless you mean that issue or PR.** GitHub turns it into a link and may close or reference an unrelated item.
- **Don't put `closes #N` or `fixes #N` in commit messages.** Put it in the PR description, where a maintainer can see and change it. Use `Refs #N` when the PR does not finish the issue.

## Scope rules

Without discussion in the issue first, PRs should not:

- change detector thresholds (they need data from many real runs)
- modify `.github/workflows/`
- change the signing or verification logic in `signer.py`
- add dependencies. The core package uses only the standard library, and optional ones (like `anthropic`) must be imported lazily so the package works without them.

## Tests

- **Run `pytest` before you push**, and keep all existing tests passing.
- **New behavior needs tests.** Bug fixes need a test that fails without the fix.
- **Tests must not need the network or API keys.** Use a fake client for external services. Tests that need Docker must skip cleanly when it is unavailable.
- **Report exact numbers.** Paste the final line of `pytest -q` from your own run, and the number of tests you added. Don't round, estimate, or copy a count from another environment.

## Project invariants

These are the things that make the logs trustworthy:

- **Every way a run can stop must be written to the signed log.** This includes errors, invalid replies, retries exhausted, and truncated output, not only successful completion. A log that shows a session ending with no reason is a bug.
- **Never put secrets in logs, error messages or tests that print them.** This includes API keys and request headers. Add a test when you touch error handling.
- **The agent must not be able to reach the signing key.** Don't mount it into the sandbox or pass it as an environment variable.
- **Untrusted output is data.** Anything from the model or sandbox must never be executed or evaluated by the host.

## Pull requests

### The description must match the diff

A PR description is a claim. Reviewers rely on it, so check every line against what you pushed.

- List what changed, as seen in the code. If you added a feature, name it. If a feature in the issue is not done, say so.
- Only claim what you ran. Write "tested on Python 3.11 / Windows 11" or "not tested against the live API", not "validated".
- Don't list a change as new if it was already on `main`.
- Include the real `pytest -q` result and the new test count.
- Use **`Closes #N`** only if the PR completes the issue. Otherwise use **`Refs #N`**.

### Checklist

- [ ] `pytest -q` passes locally (paste the last line)
- [ ] No API keys, tokens or personal paths in the diff
- [ ] No changes outside the issue's scope
- [ ] Every new stop or failure path is written to the signed log
- [ ] README or docs updated if behavior changed
- [ ] Description matches the diff, and the test numbers come from my run
- [ ] I agree to the contributor terms in the License section.
      
### Review

- PRs from forks need a maintainer to approve CI before it runs. Expect a short delay.
- Respond to review by pushing new commits. Please don't force-push over reviewed work.
- A maintainer will squash-merge and write the merge message, so it will not auto-close issues by accident.

## Reporting security problems

If you find a way for sandboxed code to read, edit or delete the signing key or logs, please don't open a public issue. Open a private security advisory on the repository instead.

## Good first contributions

- Error-signature extractors for more languages (`src/agentbox/error_signatures.py`)
- Tests and docs
- Issues labeled [`good first issue`](https://github.com/Agentboxx-dev/Agentboxx/labels/good%20first%20issue)

## License and contributor agreement

Agentboxx is released under Apache-2.0. See [LICENSE](LICENSE).

By submitting a contribution (code, tests, docs or anything else), you agree to the following terms:

1. **It's yours to give.** The contribution is your own work, or you have the right to submit it. If your employer or school has rights in your work, you have their permission.
2. **You keep your copyright.** You are not transferring ownership to anyone.
3. **You grant the project a license.** You give the Agentboxx maintainers a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, copy, modify, distribute and sublicense your contribution, **including under other license terms, such as a commercial license for paid versions of Agentboxx.**
4. **Patents.** You grant the same kind of license to any patent claims you own that your contribution necessarily infringes.
5. **The open-source version stays open.** What you contribute remains available under Apache-2.0 in the public repository.
6. **No warranty.** Your contribution is provided "as is".

**How to agree:** add this sentence to your first pull request description:

> I have read and agree to the contributor terms in CONTRIBUTING.md.
