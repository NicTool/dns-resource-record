

# Release process

in your feature branch:

- make your changes
- git add .
- .release/do.sh {major|minor|patch}
- fill in the blanks in CHANGES.md
- .release/push.sh

Upon merge to `master`:

- the new version will be published to NPM.
- a GitHub release will be published.
- a release tag will be committed to the repo.
