const { spawnSync } = require('node:child_process');
const { existsSync, statSync, readdirSync } = require('node:fs');
const { join } = require('node:path');

function requireReleaseCI(env) {
  if (
    env.GITHUB_ACTIONS !== 'true' ||
    env.GITHUB_REPOSITORY !== 'ai-ecoverse/sliccy-app' ||
    env.GITHUB_EVENT_NAME !== 'push' ||
    env.GITHUB_REF !== 'refs/heads/main'
  ) {
    throw new Error('Release requires an upstream main push in GitHub Actions');
  }
}

// Only the metadata step calls the notes model; builds and signing never see its token.
const MODEL_ENV = ['AWS_BEARER_TOKEN_BEDROCK'];

function stepEnv(env, { modelAccess = false } = {}) {
  const result = { ...env, SLICCY_RELEASE: '1' };
  if (!modelAccess) for (const name of MODEL_ENV) delete result[name];
  return result;
}

function run(command, args, context, input, options) {
  const started = Date.now();
  console.log(`Release step: ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, {
    cwd: context.cwd,
    env: stepEnv(context.env, options),
    stdio: [input === undefined ? 'inherit' : 'pipe', 'inherit', 'inherit'],
    input,
  });
  if (result.error) throw result.error;
  console.log(`Release step finished: ${command} (${((Date.now() - started) / 1000).toFixed(1)}s)`);
  if (result.status !== 0)
    throw new Error(`Release command failed: ${command} (${result.status ?? result.signal})`);
}

function verifyAssets(directory, version) {
  const expected = [`Sliccy-${version}.dmg`, `Sliccy-${version}.zip`, 'SHA256SUMS', 'appcast.xml'];
  for (const name of expected) {
    const path = join(directory, name);
    if (!existsSync(path) || !statSync(path).isFile() || statSync(path).size === 0) {
      throw new Error(`Missing release asset: ${name}`);
    }
  }
  // The publisher uses globs; refuse stale archives rather than upload them.
  for (const name of readdirSync(directory)) {
    if (
      /^Sliccy-.*\.(zip|dmg)$/.test(name) &&
      name !== 'Sliccy-notarize.zip' &&
      !expected.includes(name)
    ) {
      throw new Error(`Unexpected release archive: ${name}`);
    }
  }
}

exports.verifyConditions = async (_, context) => requireReleaseCI(context.env);
async function prepareRelease(context, execute = run) {
  requireReleaseCI(context.env);
  execute(
    'python3',
    ['script/semantic_metadata.py'],
    context,
    JSON.stringify({
      version: context.nextRelease.version,
      notes: context.nextRelease.notes,
      previousTag: context.lastRelease.gitTag,
      commits: (context.commits ?? []).map((commit) => commit.message),
    }),
    { modelAccess: true }
  );
  execute('npm', ['test'], context);
  execute('python3', ['script/cache_sparkle.py'], context);
  execute('/usr/bin/xcrun', ['swift', 'test'], context);
  execute('./script/fetch_cli.sh', [], context);
  execute('./script/build_and_run.sh', ['--build'], context);
  execute('./script/ci_sign.sh', ['dist/Sliccy.app', 'artifacts/signed'], context);
  execute('python3', ['script/prepare_release.py', 'artifacts/signed'], context);
  verifyAssets(join(context.cwd, 'artifacts/signed'), context.nextRelease.version);
}
exports.prepare = async (_, context) => prepareRelease(context);
exports.prepareRelease = prepareRelease;
exports.requireReleaseCI = requireReleaseCI;
exports.verifyAssets = verifyAssets;
exports.stepEnv = stepEnv;
