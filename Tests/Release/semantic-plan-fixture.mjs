import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import config from '../../release.config.cjs';

const { execFileSync } = await import('node:child_process');
const { default: semanticRelease } = await import('semantic-release');
const { Writable } = await import('node:stream');
const directory = mkdtempSync(join(tmpdir(), 'sliccy-semantic-plan-'));
const git = (...args) =>
  execFileSync('git', args, {
    cwd: directory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
try {
  git('init', '--bare', 'remote.git');
  git('init', '-b', 'main');
  git('config', 'user.email', 'release-test@example.invalid');
  git('config', 'user.name', 'Release Test');
  git('commit', '--allow-empty', '-m', 'Previous release');
  git('tag', 'v7.1.0');
  git('remote', 'add', 'origin', join(directory, 'remote.git'));
  git('push', 'origin', 'main', '--tags');
  git('--git-dir=remote.git', 'symbolic-ref', 'HEAD', 'refs/heads/main');
  git('commit', '--allow-empty', '-m', 'fix: recover browser links');
  git('commit', '--allow-empty', '-m', 'feat: rename connections');
  git('push', 'origin', 'main');
  const sink = new Writable({
    write(_chunk, _encoding, done) {
      done();
    },
  });
  const result = await semanticRelease(
    {
      branches: config.branches,
      tagFormat: config.tagFormat,
      repositoryUrl: join(directory, 'remote.git'),
      dryRun: true,
      ci: false,
      plugins: [
        [
          join(process.cwd(), 'node_modules/@semantic-release/commit-analyzer/index.js'),
          config.plugins[0][1],
        ],
        join(process.cwd(), 'script/semantic_release.cjs'),
      ],
    },
    {
      cwd: directory,
      stdout: sink,
      stderr: sink,
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        GITHUB_ACTIONS: 'true',
        GITHUB_REPOSITORY: 'ai-ecoverse/sliccy-app',
        GITHUB_EVENT_NAME: 'push',
        GITHUB_REF: 'refs/heads/main',
      },
    }
  );
  assert.equal(result.lastRelease.version, '7.1.0');
  assert.equal(result.nextRelease.version, '7.2.0');
  assert.equal(git('tag', '--list').trim(), 'v7.1.0');
  assert.ok(!existsSync(join(directory, 'release/version.json')));
} finally {
  rmSync(directory, { recursive: true, force: true });
}
