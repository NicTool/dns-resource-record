
# Release process

In your local repo:

- make your changes
- git add .
- `.release/do.sh` {major|minor|patch}
- fill in the blanks in CHANGELOG.md
- `.release/push.sh`

Upon merge to `master`:

- the new version will be published to NPM.
- a GitHub release will be published.
- a release tag will be committed to the repo.

## Clean

`.release/cleanup.sh`

- will switch to the master branch
- delete the release branch
