# Shared AI reviews and applicable tooling

This is the native adaptation of
[ai-ecoverse/slicc-shared-web](https://github.com/ai-ecoverse/slicc-shared-web/tree/b7a6eda4ee67e7689aacd86b4b1c0c98fb6fe6e4),
inspected at `b7a6eda4ee67e7689aacd86b4b1c0c98fb6fe6e4` (package release 2.14.4).
The adapted reviewer action steps, findings contract and review criteria retain
its Apache-2.0 attribution; [license copy](licenses/slicc-shared-web-APACHE-2.0.txt).
This is not a call to the web pipeline: that pipeline also owns browser tests,
web deployment, coverage conventions and package publishing that do not fit Sliccy.

## Reviews

PR CI keeps the existing macOS test job, saves its actual test commit and logs,
and runs two independent source reviewers on ephemeral GitHub Ubuntu runners:
Claude and Codex through Bedrock. Both see the exact PR head/base, diff, prior
reviews, issues and available native test logs. Missing logs never mean pass.
The native test job tests GitHub's PR merge commit; the recorded SHA distinguishes
that from the source reviewers' PR head. Reviewers cannot establish GUI or native
runtime behavior on Linux. They can inspect native evidence and run tooling checks.

The upstream model defaults and overrides are retained:

| Variable | Default |
|---|---|
| `CERT_BEDROCK_MODEL` | `global.anthropic.claude-opus-5-5` |
| `CERT_BEDROCK_FALLBACK_MODEL` | `global.anthropic.claude-sonnet-5-5` |
| `CODEX_BEDROCK_MODEL` | `global.openai.gpt-6.1-sol` |
| `CERT_AWS_REGION` | `us-west-2` |

There is one infrastructure/output retry per reviewer, within its 60-minute job.
A denied review is not retried to seek approval. The publisher validates the
findings, posts `review / claude` and `review / codex` statuses on the exact head,
maintains summary comments, and posts changed-line findings. Follow-ups remain
recommendations in the PR; no issues, cross-repo messages, R2 screenshots, merges,
deployments, signing or releases are created by this adaptation.

The aggregate `review` job succeeds only when setup, context, reviewer jobs and
publication all succeed and both outputs say approved. Missing credentials,
missing/invalid output, denied findings, publication failure and stale heads do
not become approval. Native `test` and `lint` are separate checks and must also
pass. All PRs, including dependency PRs and drafts, use the same review policy.
Concurrency cancels obsolete runs; publication checks that the PR head is still
current. This PR does not change branch protection or configure auto-merge.

### Required repository setup

Configure **AWS_BEARER_TOKEN_BEDROCK** as a repository Actions secret, or include
`ai-ecoverse/sliccy-app` in the organization secret's selected repositories.
A repository-level token was supplied through secure entry during PR setup;
organization secret access was not broadened. Without a token the setup/review
check fails with that specific message. The selected region/models must be
available on that Bedrock account. Local tests do not validate paid model access;
the first authenticated workflow run establishes that separately.

Reviewers receive read-only GitHub permissions and the model credential; the
separate publisher receives PR/status write permissions but no Bedrock secret.
Checkouts do not persist Git credentials, and dependency install ignores lifecycle
scripts. This is for trusted same-repository branches: reviewers execute tools on
PR content. Forks receive no secrets and fail the review setup explicitly; a
maintainer must inspect the change before moving it to a trusted branch. There is
no `pull_request_target` path that runs fork code with secrets. A same-repo PR can
change its own workflow, so branch creation rights remain a trust boundary.

Once a real PR has completed both reviews, repository owners can require native
`test`, `lint`, and the aggregate AI `review` check in branch protection. The
workflow uses ordinary PR events; no merge-queue policy is introduced here.

## Tooling adopted

- Exact `@ai-ecoverse/slicc-shared-web` package pin and its Biome preset for Node
  release/review scripts and configuration. Existing tooling receives formatting
  and an unused-import cleanup only. Swift/Python and retained proof packets are
  outside Biome's configured file set.
- Root shared Renovate preset, limited to npm, Actions, SwiftPM and annotated
  workflow pins. Shared release-age, dependency grouping and exact-pin rules are
  retained; **automerge is off** because merging can publish a signed app.
- Actionlint validates workflows, including the `xcode-27` label. Its sole
  path-specific exception preserves the intentionally disabled old capture job;
  do not remove that job's `if: false` to appease lint.
- Optional local Lefthook commands: tooling lint, automation tests and staged
  whitespace. Install explicitly with `npm run hooks:install`. No automatic
  prepare hook changes a developer's Git settings during `npm ci`.

Not adopted: web CDP/browser harnesses, TypeScript config, web deployment, web
coverage thresholds, no-comments/no-documentation policy, or the prohibition on
committed unit tests. Sliccy retains its Swift tests and security/proof comments.
The existing semantic-release and signed DMG/ZIP/Sparkle pipeline remain in charge
of publication. Renovate does not update the bundled CLI version independently of
its platform hashes: that verified binary-pin update remains a separate change.

## Checks

```
npm ci --ignore-scripts
npm run lint
npm run lint:workflows  # requires actionlint
npm test
xcrun swift test
```

Publisher tests use a local fake GitHub API, exercise actual status/comment
requests and verify malformed/missing output, denial, stale heads and comment
ownership. They do not make GitHub writes or call paid models. CI also validates
Renovate configuration against its schema.
