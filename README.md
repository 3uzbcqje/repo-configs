# repo-configs

`apply.sh` applies a security baseline to every repo owned by `6j0-org`,
`devopscoop` and `3uzbcqje` on GitHub, GitLab and Codeberg. It is idempotent
and only reports what it would change unless you pass `--apply`.

```bash
./apply.sh                    # dry run, all platforms
./apply.sh github --apply     # apply to one platform
./apply.sh --apply            # apply everywhere
```

Requires `gh` and `glab` (logged in), `jq`, `curl`, and either `fj` (logged in
to codeberg.org) or `CODEBERG_TOKEN`. Archived repos, forks, mirrors, empty
repos and GitLab projects scheduled for deletion are skipped. Exits non-zero if
any API call failed.

## What it sets

| Setting | GitHub | GitLab (Free) | Codeberg |
|---|---|---|---|
| Default branch protected | ✅ ruleset | ✅ protected branch | ✅ branch protection |
| No force push to default branch | ✅ | ✅ | ✅ always, when protected |
| No deleting the default branch | ✅ | ✅ | ✅ always, when protected |
| Signed commits required | ✅ | ❌ Premium only | ✅ |
| Applies to admins too | ✅ no bypass actors | ✅ | ✅ `apply_to_admins` |
| Delete branch after merge | ✅ | default only¹ | default only¹ |
| Immutable releases | ✅ | ❌ no such feature | ❌ no such feature |
| Dependabot alerts + security update PRs | ✅ | — | — |
| Secret scanning + push protection | ✅ public repos | — | — |
| Private vulnerability reporting | ✅ public repos | — | — |
| Actions: read-only `GITHUB_TOKEN`, can't approve PRs | ✅ | — | — |
| Actions: approval needed for all outside contributors' PR workflows | ✅ public repos | — | — |

¹ Only sets whether the "delete source branch" checkbox starts ticked on new
merge requests.

Direct pushes to the default branch are still allowed; PRs are not required.

### Limits

- **GitHub private repos** on a Free account can't use rulesets or branch
  protection at all (`3uzbcqje/resume`, `3uzbcqje/home`). The script skips them
  with a note. Making them public or upgrading to GitHub Pro would fix that.
- **Signed commits** only pass if your signing key is uploaded to each platform,
  which it already is. On GitHub, merge PRs with *squash* or *merge commit*,
  which GitHub signs. *Rebase and merge* creates unsigned commits and will be
  rejected.
- **Immutable releases** (GitHub) lock a release's tag and assets once it is
  published. Plain tags that have no release attached aren't affected.
- **New repos** aren't covered until you run the script again.
