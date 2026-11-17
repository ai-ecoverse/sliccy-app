// Adapted from slicc-shared-web b7a6eda4 (Apache-2.0); no issue creation or R2 upload.
import { readFile } from 'node:fs/promises';
import { agents, parseFindings, statusFor, summaryFor } from './findings.mjs';

const env = process.env;
const event = JSON.parse(await readFile(env.GITHUB_EVENT_PATH, 'utf8'));
const pr = event.pull_request;
const sha = pr.head.sha;
const root = `repos/${env.GITHUB_REPOSITORY}`;
const call = async (method, path, body) => {
  const response = await fetch(`${env.GITHUB_API_URL}/${path}`, {
    method,
    headers: {
      authorization: `Bearer ${env.GH_TOKEN}`,
      accept: 'application/vnd.github+json',
      'content-type': 'application/json',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) throw new Error(`${method} ${path}: HTTP ${response.status}`);
  return response.json();
};
const list = async (path) => {
  const items = [];
  // Refuse truncation rather than silently miss old bot comments.
  for (let page = 1; page <= 100; page++) {
    const batch = await call('GET', `${path}?per_page=100&page=${page}`);
    items.push(...batch);
    if (batch.length < 100) return items;
  }
  throw new Error('Comment pagination limit reached');
};
const current = await call('GET', `${root}/pulls/${pr.number}`);
if (current.state !== 'open' || current.head.sha !== sha)
  throw new Error('PR closed or head changed; stale findings will not be posted');
const comments = await list(`${root}/issues/${pr.number}/comments`);
let accepted = true;
for (const agent of agents) {
  let findings;
  try {
    findings = parseFindings(await readFile(`findings/findings-${agent}/findings.json`, 'utf8'));
  } catch {
    console.error(`${agent}: missing or invalid findings (not approval)`);
  }
  const state = statusFor(findings);
  if (state !== 'success') accepted = false;
  await call('POST', `${root}/statuses/${sha}`, {
    state,
    context: `review / ${agent}`,
    description: findings
      ? `${agent}: ${findings.verdict}`
      : `${agent}: missing or invalid findings`,
    target_url: `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`,
  });
  if (!findings) continue;
  const marker = `<!-- slicc-review:${agent} -->`;
  const prior = comments.find(
    (comment) => comment.user?.login === 'github-actions[bot]' && comment.body.startsWith(marker)
  );
  const body = summaryFor(agent, sha, findings);
  if (body.length > 60000) throw new Error(`${agent}: summary too long`);
  await call(
    prior ? 'PATCH' : 'POST',
    prior ? `${root}/issues/comments/${prior.id}` : `${root}/issues/${pr.number}/comments`,
    { body }
  );
  const inline = await list(`${root}/pulls/${pr.number}/comments`);
  for (const comment of findings.comments) {
    const text = `**${agent}:** ${comment.body}`;
    if (
      inline.some(
        (item) =>
          item.user?.login === 'github-actions[bot]' &&
          item.commit_id === sha &&
          item.path === comment.path &&
          item.line === comment.line &&
          item.body === text
      )
    )
      continue;
    try {
      await call('POST', `${root}/pulls/${pr.number}/comments`, {
        commit_id: sha,
        path: comment.path,
        line: comment.line,
        side: 'RIGHT',
        body: text,
      });
    } catch (error) {
      // Preserve the artifact and finish publishing both agents; delivery still fails CI.
      accepted = false;
      console.error(`${agent}: inline comment publication failed: ${error.message}`);
    }
  }
}
if (!accepted) process.exitCode = 1;
