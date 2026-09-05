# Changesets

Each user-visible pull request adds a changeset describing the affected package or packages and
their SemVer impact:

```bash
pnpm changeset
```

Packages version independently. Select the packages whose public behavior changed; do not add every
dependent by hand. Changesets updates internal dependency and peer ranges, and adds a dependent patch
release when a new internal version would otherwise fall outside its declared range.

The Version Packages pull request is the only place package versions and package changelogs are
normally edited. See [`../RELEASING.md`](../RELEASING.md) for the complete process.
