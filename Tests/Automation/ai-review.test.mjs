import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { parseFindings, statusFor, summaryFor } from '../../script/ai-review/findings.mjs';

const approved = { verdict: 'approved', summary: 'Reviewed the change.', comments: [], issues: [] };
const denied = { ...approved, verdict: 'denied' };
const sha = 'a'.repeat(40);
const otherSHA = 'b'.repeat(40);

test('missing, malformed, oversized and unknown verdicts cannot become approval', () => {
  assert.equal(statusFor(undefined), 'error');
  assert.equal(statusFor(parseFindings(JSON.stringify(approved))), 'success');
  assert.equal(statusFor(parseFindings(JSON.stringify(denied))), 'failure');
  for (const value of [
    null,
    {},
    { ...approved, verdict: 'approve' },
    { ...approved, summary: '' },
    { ...approved, comments: 'none' },
    { ...approved, extra: true },
    {
      ...approved,
      issues: [{ repo: 'owner/repo', title: 'Follow up', body: 'Details', security: 'false' }],
    },
    { ...approved, comments: [{ path: '../secret', line: 1, body: 'Details' }] },
    { ...approved, comments: [{ path: 'Sources/App.swift', line: 0, body: 'Details' }] },
  ]) {
    assert.throws(() => parseFindings(JSON.stringify(value)));
  }
  assert.throws(() => parseFindings('x'.repeat(1024 * 1024 + 1)));
});

test('security recommendations stay out of the follow-up list', () => {
  const findings = {
    ...approved,
    issues: [
      { repo: 'owner/repo', title: 'Security', body: 'Not for issue creation', security: true },
      { repo: 'owner/repo', title: 'UI follow-up', body: 'Nonblocking details', security: false },
    ],
  };
  const body = summaryFor('claude', sha, parseFindings(JSON.stringify(findings)));
  assert.match(body, /UI follow-up/);
  assert.doesNotMatch(body, /Not for issue creation/);
  assert.match(body, /not filed/);
});

async function publish(t, findings, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'sliccy-review-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const calls = [];
  const server = createServer(async (request, response) => {
    let data = '';
    for await (const chunk of request) data += chunk;
    const body = data ? JSON.parse(data) : undefined;
    calls.push({ method: request.method, path: request.url, body });
    response.setHeader('Content-Type', 'application/json');
    if (request.url === '/repos/owner/repo/pulls/12' && request.method === 'GET') {
      response.end(JSON.stringify({ state: 'open', head: { sha: options.head ?? sha } }));
    } else if (request.method === 'GET') {
      const page = Number(new URL(request.url, 'http://test').searchParams.get('page') ?? 1);
      response.end(JSON.stringify(options.pages?.[page - 1] ?? options.comments ?? []));
    } else if (
      options.rejectInline &&
      request.method === 'POST' &&
      request.url.endsWith('/pulls/12/comments')
    ) {
      response.statusCode = 422;
      response.end(JSON.stringify({ message: 'Line not in diff' }));
    } else {
      response.end(JSON.stringify({ id: 123 }));
    }
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => new Promise((done) => server.close(done)));
  const event = join(dir, 'event.json');
  await writeFile(event, JSON.stringify({ pull_request: { number: 12, head: { sha } } }));
  for (const [agent, value] of Object.entries(findings)) {
    await mkdir(join(dir, `findings/findings-${agent}`), { recursive: true });
    await writeFile(join(dir, `findings/findings-${agent}/findings.json`), JSON.stringify(value));
  }
  let exit = 0;
  try {
    await promisify(execFile)(process.execPath, [resolve('script/ai-review/publish.mjs')], {
      cwd: dir,
      timeout: 10000,
      env: {
        ...process.env,
        GITHUB_EVENT_PATH: event,
        GITHUB_API_URL: `http://127.0.0.1:${server.address().port}`,
        GITHUB_REPOSITORY: 'owner/repo',
        GH_TOKEN: 'synthetic-token',
        GITHUB_RUN_ID: '123',
        GITHUB_SERVER_URL: 'https://github.com',
      },
    });
  } catch (error) {
    exit = error.code;
  }
  return { exit, calls };
}

test('publisher binds both statuses to the reviewed SHA, posts comments, and never creates issues', async (t) => {
  const findings = {
    ...approved,
    comments: [{ path: 'Sources/App.swift', line: 12, body: 'Nonblocking note.' }],
    issues: [{ repo: 'other/project', title: 'Later', body: 'Follow up', security: false }],
  };
  const { exit, calls } = await publish(t, { claude: findings, codex: approved });
  assert.equal(exit, 0);
  const statuses = calls.filter((call) => call.path.includes('/statuses/'));
  assert.deepEqual(
    statuses.map((call) => call.body.context),
    ['review / claude', 'review / codex']
  );
  assert.ok(statuses.every((call) => call.path.endsWith(sha) && call.body.state === 'success'));
  const inline = calls.find(
    (call) => call.method === 'POST' && call.path.endsWith('/pulls/12/comments')
  );
  assert.equal(inline.body.commit_id, sha);
  assert.ok(calls.every((call) => call.path.startsWith('/repos/owner/repo/')));
  assert.ok(!calls.some((call) => call.path.endsWith('/issues') && call.method === 'POST'));
});

test('denial or missing reviewer fails aggregate, not a green skipped reviewer', async (t) => {
  const deniedResult = await publish(t, { claude: denied, codex: approved });
  assert.equal(deniedResult.exit, 1);
  assert.deepEqual(
    deniedResult.calls
      .filter((call) => call.path.includes('/statuses/'))
      .map((call) => call.body.state),
    ['failure', 'success']
  );
  const missing = await publish(t, { claude: approved });
  assert.equal(missing.exit, 1);
  assert.deepEqual(
    missing.calls.filter((call) => call.path.includes('/statuses/')).map((call) => call.body.state),
    ['success', 'error']
  );
});

test('stale head refuses all writes, and a user marker cannot cause another comment to be edited', async (t) => {
  const stale = await publish(t, { claude: approved, codex: approved }, { head: otherSHA });
  assert.notEqual(stale.exit, 0);
  assert.ok(stale.calls.every((call) => call.method === 'GET'));
  const spoofed = await publish(
    t,
    { claude: approved, codex: approved },
    {
      comments: [
        { id: 999, user: { login: 'a-person' }, body: '<!-- slicc-review:claude -->spoofed' },
      ],
    }
  );
  assert.equal(spoofed.exit, 0);
  assert.ok(spoofed.calls.every((call) => call.method !== 'PATCH'));
});

test('one missing artifact cannot flatten the other reviewer into an ambiguous path', async () => {
  const workflow = await readFile('.github/workflows/ai-review.yml', 'utf8');
  for (const agent of ['claude', 'codex']) {
    assert.ok(
      workflow.includes(`name: findings-${agent}\n          path: findings/findings-${agent}`)
    );
  }
  assert.ok(!workflow.includes('pattern: findings-*'));
});

test('a rejected inline comment fails delivery but preserves both reviewer summaries and statuses', async (t) => {
  const findings = {
    ...approved,
    comments: [{ path: 'Sources/App.swift', line: 12, body: 'Note' }],
  };
  const { exit, calls } = await publish(
    t,
    { claude: findings, codex: approved },
    { rejectInline: true }
  );
  assert.equal(exit, 1);
  assert.equal(calls.filter((call) => call.path.includes('/statuses/')).length, 2);
  assert.equal(
    calls.filter((call) => call.method === 'POST' && call.path.endsWith('/issues/12/comments'))
      .length,
    2
  );
});

test('pagination finds an existing bot summary and inline note beyond the first hundred', async (t) => {
  const note = { path: 'Sources/App.swift', line: 12, body: 'Note' };
  const pages = [
    Array.from({ length: 100 }, (_, id) => ({ id, body: 'Old', user: { login: 'person' } })),
    [
      { id: 101, user: { login: 'github-actions[bot]' }, body: '<!-- slicc-review:claude -->Old' },
      {
        id: 102,
        user: { login: 'github-actions[bot]' },
        body: '**claude:** Note',
        commit_id: sha,
        path: note.path,
        line: note.line,
      },
    ],
  ];
  const { exit, calls } = await publish(
    t,
    { claude: { ...approved, comments: [note] }, codex: approved },
    { pages }
  );
  assert.equal(exit, 0);
  assert.ok(
    calls.some((call) => call.method === 'PATCH' && call.path.endsWith('/issues/comments/101'))
  );
  assert.ok(
    !calls.some((call) => call.method === 'POST' && call.path.endsWith('/pulls/12/comments'))
  );
});
