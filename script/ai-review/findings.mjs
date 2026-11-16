// Findings contract adapted from slicc-shared-web; validation is specific to this publisher.
export const agents = ['claude', 'codex'];

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}
function text(value, maximum = 12000) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= maximum;
}
export function parseFindings(raw) {
  if (Buffer.byteLength(raw) > 1024 * 1024) throw new Error('Oversized findings');
  const value = JSON.parse(raw);
  if (
    !exactKeys(value, ['verdict', 'summary', 'comments', 'issues']) ||
    !['approved', 'denied'].includes(value.verdict) ||
    !text(value.summary) ||
    !Array.isArray(value.comments) ||
    value.comments.length > 50 ||
    !Array.isArray(value.issues) ||
    value.issues.length > 20
  )
    throw new Error('Invalid findings');
  for (const item of value.comments) {
    if (
      !exactKeys(item, ['path', 'line', 'body']) ||
      !text(item.path, 500) ||
      item.path.startsWith('/') ||
      item.path.split('/').includes('..') ||
      /[\x00-\x1f\\]/.test(item.path) ||
      !Number.isSafeInteger(item.line) ||
      item.line < 1 ||
      !text(item.body)
    )
      throw new Error('Invalid line comment');
  }
  for (const item of value.issues) {
    if (
      !exactKeys(item, ['repo', 'title', 'body', 'security']) ||
      !/^[\w.-]+\/[\w.-]+$/.test(item.repo) ||
      !text(item.title, 256) ||
      !text(item.body) ||
      typeof item.security !== 'boolean'
    )
      throw new Error('Invalid follow-up');
  }
  return value;
}

export function statusFor(findings) {
  return !findings ? 'error' : findings.verdict === 'approved' ? 'success' : 'failure';
}
export function summaryFor(agent, sha, findings) {
  const issues = findings.issues.filter((issue) => issue.security === false);
  const recommendations = issues
    .map((issue) => `- **${issue.repo}: ${issue.title}**\n\n${issue.body}`)
    .join('\n\n');
  return (
    `<!-- slicc-review:${agent} -->\n**${agent}: ${findings.verdict}** on ${sha}\n\n${findings.summary}` +
    (recommendations ? `\n\nFollow-up recommendations (not filed):\n\n${recommendations}` : '')
  );
}
