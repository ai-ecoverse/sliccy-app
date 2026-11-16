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
const current = await call('GET', `${root}/pulls/${pr.number}`);
if (current.state !== 'open' || current.head.sha !== sha)
  throw new Error('PR closed or head changed; stale findings will not be posted');
const comments = await call(
  'GET',
  `${root}/issues/${pr.number}/comments?per_page=100&sort=updated&direction=desc`
);
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
  const inline = await call('GET', `${root}/pulls/${pr.number}/comments?per_page=100`);
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
    await call('POST', `${root}/pulls/${pr.number}/comments`, {
      commit_id: sha,
      path: comment.path,
      line: comment.line,
      side: 'RIGHT',
      body: text,
    });
  }
}
if (!accepted) process.exitCode = 1;
