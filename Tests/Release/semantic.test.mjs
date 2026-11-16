import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeCommits } from '@semantic-release/commit-analyzer';
import { generateNotes } from '@semantic-release/release-notes-generator';
import { glob } from 'tinyglobby';
import config from '../../release.config.cjs';
import plugin from '../../script/semantic_release.cjs';
const logger = { log() {} };

for (const [message, expected] of [
  ['fix: reconnect after network loss', 'patch'],
  ['feat: rename connections', 'minor'],
  ['feat!: change the connection contract', 'major'],
  ['fix: change the connection contract\n\nBREAKING CHANGE: old settings no longer work', 'major'],
  ['docs: clarify update behavior', null],
  ['chore: update development tools', null],
]) {
  test(`release type: ${message.split('\n')[0]}`, async () => {
    assert.equal(await analyzeCommits(config.plugins[0][1], {
      cwd: process.cwd(), commits: [{ message, hash: 'abcdef123456' }], logger,
    }), expected);
  });
}

test('release notes link the actual fixes', async () => {
  const notes = await generateNotes(config.plugins[1][1], {
    cwd: process.cwd(), logger, options: { repositoryUrl: config.repositoryUrl },
    commits: [{ message: 'fix: restore disconnected browser links', hash: 'a'.repeat(40) }],
    lastRelease: { gitTag: 'v7.1.0' }, nextRelease: { version: '7.2.0', gitTag: 'v7.2.0' },
  });
  assert.match(notes, /restore disconnected browser links/);
  assert.match(notes, /v7\.1\.0\.\.\.v7\.2\.0/);
});

test('native release preparation refuses local, PR and foreign contexts', () => {
  const env = { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'ai-ecoverse/sliccy-app',
    GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/main' };
  plugin.requireReleaseCI(env);
  for (const [key, value] of [['GITHUB_ACTIONS', 'false'], ['GITHUB_REPOSITORY', 'fork/app'],
    ['GITHUB_EVENT_NAME', 'pull_request'], ['GITHUB_REF', 'refs/heads/topic']]) {
    assert.throws(() => plugin.requireReleaseCI({ ...env, [key]: value }));
  }
});

test('publisher includes exactly the verified public assets', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'sliccy-release-assets-'));
  try {
    const expected = ['Sliccy-7.2.0.dmg', 'Sliccy-7.2.0.zip', 'SHA256SUMS', 'appcast.xml'];
    for (const name of [...expected, 'Sliccy-notarize.zip', 'signing.txt', 'notarization.json']) {
      writeFileSync(join(directory, name), 'fixture');
    }
    plugin.verifyAssets(directory, '7.2.0');
    const assets = config.plugins.at(-1)[1].assets;
    const matches = (await Promise.all(assets.map(({ path }) => glob(
      (Array.isArray(path) ? path : [path]).map(p => p.replace('artifacts/signed/', '')), { cwd: directory }
    )))).flat();
    assert.deepEqual(matches.sort(), expected.sort());
    writeFileSync(join(directory, 'Sliccy-7.1.0.zip'), 'stale');
    assert.throws(() => plugin.verifyAssets(directory, '7.2.0'), /Unexpected release archive/);
    rmSync(join(directory, 'Sliccy-7.1.0.zip'));
    rmSync(join(directory, 'appcast.xml'));
    assert.throws(() => plugin.verifyAssets(directory, '7.2.0'), /Missing release asset/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('signing and update verification failures abort preparation', async () => {
  const env = { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'ai-ecoverse/sliccy-app',
    GITHUB_EVENT_NAME: 'push', GITHUB_REF: 'refs/heads/main' };
  for (const failingStep of ['./script/ci_sign.sh', 'script/prepare_release.py']) {
    const calls = [];
    await assert.rejects(plugin.prepareRelease({ cwd: process.cwd(), env,
      nextRelease: { version: '7.2.0', notes: 'Notes' }, lastRelease: { gitTag: 'v7.1.0' },
    }, (command, args) => {
      calls.push([command, ...args]);
      if ([command, ...args].includes(failingStep)) throw new Error('injected verification failure');
    }), /injected verification failure/);
    assert.ok(calls.at(-1).includes(failingStep));
    assert.ok(calls.some(args => args.includes('script/semantic_metadata.py')));
    if (failingStep === './script/ci_sign.sh') {
      assert.ok(!calls.some(args => args.includes('script/prepare_release.py')));
    }
  }
});

test('semantic-release plans from a published tag without writing a tag in dry-run', async () => {
  const { execFileSync } = await import('node:child_process');
  execFileSync(process.execPath, ['Tests/Release/semantic-plan-fixture.mjs'], {
    cwd: process.cwd(), env: { PATH: process.env.PATH, HOME: process.env.HOME },
    stdio: 'pipe', timeout: 30000,
  });
});
