// Adapted for macOS from slicc-shared-web b7a6eda4 (Apache-2.0).
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';

const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, 'utf8'));
const pr = event.pull_request;
const dir = `${process.env.RUNNER_TEMP}/review/context`;
await mkdir(dir, { recursive: true });
const git = (...args) => execFileSync('git', args, { maxBuffer: 32 * 1024 * 1024 });
await writeFile(`${dir}/pr.json`, JSON.stringify(pr, null, 2));
await writeFile(`${dir}/pr.diff`, git('diff', `${pr.base.sha}...${pr.head.sha}`));
await writeFile(
  `${dir}/files.txt`,
  git('diff', '--name-status', `${pr.base.sha}...${pr.head.sha}`)
);
await writeFile(
  `${dir}/commits.txt`,
  git('log', '--format=%H%x09%an%x09%s', `${pr.base.sha}..${pr.head.sha}`)
);
const missing = [];
const repo = process.env.GITHUB_REPOSITORY;
for (const [name, path] of Object.entries({
  comments: `issues/${pr.number}/comments`,
  reviews: `pulls/${pr.number}/reviews`,
  'review-comments': `pulls/${pr.number}/comments`,
  issues: 'issues?state=open&sort=updated',
  pulls: 'pulls?state=all&sort=updated',
})) {
  try {
    const items = [];
    for (let page = 1; page <= 3; page++) {
      const response = await fetch(
        `${process.env.GITHUB_API_URL}/repos/${repo}/${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`,
        {
          headers: {
            authorization: `Bearer ${process.env.GH_TOKEN}`,
            accept: 'application/vnd.github+json',
          },
          signal: AbortSignal.timeout(20_000),
        }
      );
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const batch = await response.json();
      items.push(...batch);
      if (batch.length < 100) break;
      if (page === 3) missing.push(`${name}: truncated after 300 entries`);
    }
    await writeFile(`${dir}/${name}.json`, JSON.stringify(items));
  } catch (error) {
    missing.push(`${name}: ${error.message}`);
  }
}
await writeFile(`${dir}/missing.txt`, missing.join('\n'));
