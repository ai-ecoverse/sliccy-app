module.exports = {
  branches: ['main'],
  repositoryUrl: 'https://github.com/ai-ecoverse/sliccy-app.git',
  tagFormat: 'v${version}',
  plugins: [
    ['@semantic-release/commit-analyzer', { preset: 'conventionalcommits' }],
    ['@semantic-release/release-notes-generator', { preset: 'conventionalcommits' }],
    './script/semantic_release.cjs',
    ['@semantic-release/github', {
      successCommentCondition: false,
      failCommentCondition: false,
      releasedLabels: false,
      releaseNameTemplate: 'Sliccy <%= nextRelease.version %>',
      assets: [
        { path: 'artifacts/signed/Sliccy-*.dmg' },
        { path: ['artifacts/signed/Sliccy-*.zip', '!artifacts/signed/Sliccy-notarize.zip'] },
        { path: 'artifacts/signed/SHA256SUMS' },
        { path: 'artifacts/signed/appcast.xml' },
      ],
    }],
  ],
};
