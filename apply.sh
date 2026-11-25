#!/usr/bin/env bash
# Apply baseline security settings to every repo in OWNERS on GitHub, GitLab
# and Codeberg. Idempotent. Shows what it would change unless --apply is given.
#
#   ./apply.sh [github] [gitlab] [codeberg] [--apply]
#
# Auth: uses your existing `gh` and `glab` logins. For Codeberg it uses
# $CODEBERG_TOKEN if set, otherwise the token `fj` stores after `fj auth login`.
set -euo pipefail

OWNERS=(6j0-org devopscoop 3uzbcqje)
CODEBERG_HOST=codeberg.org
RULESET_NAME=default-branch-baseline

# GitHub repository ruleset for the default branch: no deletion, no force
# push. Signed commits aren't required; updating an existing ruleset drops its
# required_signatures rule. No bypass actors, so it applies to admins too.
ruleset() {
  jq -cn --arg name "$RULESET_NAME" '{
    name: $name,
    target: "branch",
    enforcement: "active",
    bypass_actors: [],
    conditions: {ref_name: {include: ["~DEFAULT_BRANCH"], exclude: []}},
    rules: [{type: "deletion"}, {type: "non_fast_forward"}]
  }'
}

usage() { sed -n '2,8s/^# \{0,1\}//p' "$0"; }

APPLY=false
PLATFORMS=()
for arg in "$@"; do
  case $arg in
    --apply) APPLY=true ;;
    github | gitlab | codeberg) PLATFORMS+=("$arg") ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
((${#PLATFORMS[@]})) || PLATFORMS=(github gitlab codeberg)

# --- output / change tracking ------------------------------------------------
CHANGES=0
ERRORS=0
ok()   { printf '  ok      %s\n' "$*"; }
skip() { printf '  skip    %s\n' "$*"; }
fail() { printf '  ERROR   %s\n' "$*" >&2; ERRORS=$((ERRORS + 1)); }

# change <label> <cmd...>: run cmd only with --apply.
change() {
  local label=$1 out
  shift
  CHANGES=$((CHANGES + 1))
  if ! $APPLY; then
    printf '  would   %s\n' "$label"
  elif out=$("$@" 2>&1); then
    printf '  set     %s\n' "$label"
  else
    fail "$label: $(tr '\n' ' ' <<<"$out")"
  fi
}

# jqv <filter> <json>: jq -r on a string argument.
jqv() { jq -r "$1" <<<"$2"; }

# setting <label> <want> <get-cmd...> -- <set-cmd...>
# Runs get-cmd; if its output differs from want, runs set-cmd via change().
setting() {
  local label=$1 want=$2 have get=()
  shift 2
  while [[ $1 != -- ]]; do get+=("$1"); shift; done
  shift
  if ! have=$("${get[@]}" 2>&1); then
    fail "$label: $(tr '\n' ' ' <<<"$have")"
  elif [[ $have == "$want" ]]; then
    ok "$label"
  else
    change "$label ($have -> $want)" "$@"
  fi
}

# --- GitHub ------------------------------------------------------------------
gh_json() { gh api -X "$1" "$2" --input - <<<"$3"; }

gh_vuln_alerts() {
  # 204 when enabled, 404 when disabled.
  if gh api "repos/$1/vulnerability-alerts" >/dev/null 2>&1; then echo true; else echo false; fi
}

gh_watching() {
  # Prints "<subscribed> <ignored>"; the API returns 404 when not watching.
  local out
  if out=$(gh api "repos/$1/subscription" --jq '"\(.subscribed) \(.ignored)"' 2>&1); then
    echo "$out"
  elif [[ $out == *'HTTP 404'* ]]; then
    echo "false false"
  else
    echo "$out"
    return 1
  fi
}

gh_ruleset() {
  local repo=$1 rulesets id current want
  want=$(ruleset)
  if ! rulesets=$(gh api "repos/$repo/rulesets?includes_parents=false" 2>&1); then
    if [[ $rulesets == *Upgrade* ]]; then
      skip "default branch ruleset (private repos need GitHub Pro)"
    else
      fail "list rulesets: $rulesets"
    fi
    return 0
  fi
  id=$(jq -r --arg n "$RULESET_NAME" '.[] | select(.name == $n) | .id' <<<"$rulesets")
  if [[ -z $id ]]; then
    change "create ruleset $RULESET_NAME" gh_json POST "repos/$repo/rulesets" "$want"
    return 0
  fi
  if ! current=$(gh api "repos/$repo/rulesets/$id" 2>&1); then
    fail "get ruleset: $current"
    return 0
  fi
  if jq -e --argjson want "$want" '
      def norm: {
        enforcement, target,
        bypass: (.bypass_actors // [] | length),
        include: (.conditions.ref_name.include | sort),
        exclude: (.conditions.ref_name.exclude | sort),
        rules: ([.rules[].type] | sort)
      };
      norm == ($want | norm)' <<<"$current" >/dev/null; then
    ok "ruleset $RULESET_NAME"
  else
    change "update ruleset $RULESET_NAME" gh_json PUT "repos/$repo/rulesets/$id" "$want"
  fi
}

github_repo() {
  local repo=$1 info saa
  echo "github: $repo"
  if ! info=$(gh api "repos/$repo" 2>&1); then fail "get repo: $info"; return 0; fi

  gh_ruleset "$repo"

  setting "delete branch on merge" true \
    jqv .delete_branch_on_merge "$info" -- \
    gh api -X PATCH "repos/$repo" -F delete_branch_on_merge=true

  setting "immutable releases" true \
    gh api "repos/$repo/immutable-releases" --jq .enabled -- \
    gh api -X PUT "repos/$repo/immutable-releases"

  # Dependabot off. Security updates depend on alerts, so disable them first.
  setting "dependabot security updates disabled" false \
    gh api "repos/$repo/automated-security-fixes" --jq .enabled -- \
    gh api -X DELETE "repos/$repo/automated-security-fixes"

  setting "dependabot alerts disabled" false \
    gh_vuln_alerts "$repo" -- \
    gh api -X DELETE "repos/$repo/vulnerability-alerts"

  setting "actions: read-only GITHUB_TOKEN, can't approve PRs" "read false" \
    gh api "repos/$repo/actions/permissions/workflow" \
      --jq '"\(.default_workflow_permissions) \(.can_approve_pull_request_reviews)"' -- \
    gh_json PUT "repos/$repo/actions/permissions/workflow" \
      '{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}'

  # Default notifications: not watching or ignoring ("Participating and
  # @mentions"). Watching only offers All Activity via the API, which is noisy.
  if $GH_CAN_WATCH; then
    setting "notifications: participating and @mentions (not watching)" "false false" \
      gh_watching "$repo" -- \
      gh api -X DELETE "repos/$repo/subscription"
  fi

  # Free plans only offer these on public repos.
  if [[ $(jq -r .private <<<"$info") == true ]]; then
    skip "secret scanning, private vuln reporting, fork PR approval (public repos only)"
    return 0
  fi

  saa=$(jq -r '[.security_and_analysis.secret_scanning.status,
                .security_and_analysis.secret_scanning_push_protection.status] | join(" ")' <<<"$info")
  setting "secret scanning + push protection" "enabled enabled" \
    echo "$saa" -- \
    gh_json PATCH "repos/$repo" \
      '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}'

  setting "private vulnerability reporting" true \
    gh api "repos/$repo/private-vulnerability-reporting" --jq .enabled -- \
    gh api -X PUT "repos/$repo/private-vulnerability-reporting"

  setting "actions: approve workflows for all outside contributors" all_external_contributors \
    gh api "repos/$repo/actions/permissions/fork-pr-contributor-approval" --jq .approval_policy -- \
    gh_json PUT "repos/$repo/actions/permissions/fork-pr-contributor-approval" \
      '{"approval_policy":"all_external_contributors"}'
}

run_github() {
  local owner line repo
  # The watch API needs the notifications token scope; check once up front.
  GH_CAN_WATCH=true
  if ! gh api 'notifications?per_page=1' >/dev/null 2>&1; then
    GH_CAN_WATCH=false
    fail "github: can't manage repo watching; run: gh auth refresh -h github.com -s notifications"
  fi
  for owner in "${OWNERS[@]}"; do
    while read -r -u 3 line; do
      repo=${line%% *}
      case $line in
        *' archived') echo "github: $repo"; skip "archived" ;;
        *' fork') echo "github: $repo"; skip "fork" ;;
        *) github_repo "$repo" ;;
      esac
    done 3< <(gh repo list "$owner" --limit 1000 --json nameWithOwner,isArchived,isFork \
      --jq '.[] | "\(.nameWithOwner) \(if .isArchived then "archived" elif .isFork then "fork" else "-" end)"')
  done
}

# --- GitLab ------------------------------------------------------------------
urlenc() { jq -rn --arg s "$1" '$s | @uri'; }

gl_notify_level() { glab api "projects/$1/notification_settings" | jq -r .level; }

gitlab_project() {
  local p=$1 id path branch prot
  id=$(jq -r .id <<<"$p")
  path=$(jq -r .path_with_namespace <<<"$p")
  branch=$(jq -r '.default_branch // empty' <<<"$p")
  echo "gitlab: $path"

  # Default notifications: follow the account-wide level.
  setting "notifications: global (account default)" global \
    gl_notify_level "$id" -- \
    glab api -X PUT "projects/$id/notification_settings" -f level=global

  if [[ -z $branch ]]; then
    skip "empty repository"
    return 0
  fi

  if prot=$(glab api "projects/$id/protected_branches/$(urlenc "$branch")" 2>&1); then
    setting "$branch: force push blocked" false \
      jqv .allow_force_push "$prot" -- \
      glab api -X PATCH "projects/$id/protected_branches/$(urlenc "$branch")" -F allow_force_push=false
  elif [[ $prot == *404* ]]; then
    change "protect $branch (maintainers push/merge, no force push)" \
      glab api -X POST "projects/$id/protected_branches" -f "name=$branch" \
        -F push_access_level=40 -F merge_access_level=40 -F allow_force_push=false
  else
    fail "get protected branch: $prot"
  fi

  setting "delete source branch on merge (default)" true \
    jqv .remove_source_branch_after_merge "$p" -- \
    glab api -X PUT "projects/$id" -F remove_source_branch_after_merge=true

  # GitLab's own merge commits are unsigned, so mirrors that require signed
  # commits reject them. Fast-forward moves the branch to your signed commits.
  setting "merge method: fast-forward" ff \
    jqv .merge_method "$p" -- \
    glab api -X PUT "projects/$id" -f merge_method=ff
}

run_gitlab() {
  local owner kind list p
  for owner in "${OWNERS[@]}"; do
    if ! kind=$(glab api "namespaces/$(urlenc "$owner")" 2>&1 | jq -r .kind); then
      fail "gitlab: look up namespace $owner"
      continue
    fi
    if [[ $kind == user ]]; then
      list="users/$(urlenc "$owner")/projects?per_page=100"
    else
      list="groups/$(urlenc "$owner")/projects?per_page=100&include_subgroups=true&with_shared=false"
    fi
    while read -r -u 3 p; do
      if [[ $(jq -r .archived <<<"$p") == true ]]; then
        echo "gitlab: $(jq -r .path_with_namespace <<<"$p")"; skip "archived"
      elif [[ $(jq -r '.forked_from_project != null' <<<"$p") == true ]]; then
        echo "gitlab: $(jq -r .path_with_namespace <<<"$p")"; skip "fork"
      elif [[ $(jq -r '.marked_for_deletion_on != null' <<<"$p") == true ]]; then
        echo "gitlab: $(jq -r .path_with_namespace <<<"$p")"; skip "scheduled for deletion"
      else
        gitlab_project "$p"
      fi
    done 3< <(glab api --paginate "$list" | jq -c '.[]')
  done
}

# --- Codeberg (Forgejo) ------------------------------------------------------
# fj has no branch protection commands or raw API passthrough, so use curl.

# cb <method> <path> [json]: prints body on 2xx; returns 4 on 404, 1 otherwise.
cb() {
  local method=$1 path=$2 data=${3:-} out code
  local args=(-sS -X "$method" -H "Authorization: token $CODEBERG_TOKEN"
              -H 'Content-Type: application/json' -w '\n%{http_code}')
  if [[ -n $data ]]; then args+=(--data "$data"); fi
  out=$(curl "${args[@]}" "https://$CODEBERG_HOST/api/v1/$path") || return 1
  code=${out##*$'\n'}
  out=${out%$'\n'*}
  if [[ $code == 2* ]]; then printf '%s' "$out"; return 0; fi
  printf 'HTTP %s: %s\n' "$code" "$out" >&2
  if [[ $code == 404 ]]; then return 4; fi
  return 1
}

codeberg_token() {
  [[ -n ${CODEBERG_TOKEN:-} ]] && return 0
  # Any authenticated fj call refreshes its stored OAuth token if it expired.
  # Run it outside this repo: fj parses the cwd's git remotes even with -H and
  # fails on non-URL-like ones (e.g. rad://).
  (cd / && fj -H "$CODEBERG_HOST" whoami >/dev/null) ||
    echo "codeberg: 'fj whoami' failed; the stored token may be expired" >&2
  CODEBERG_TOKEN=$(jq -r --arg h "$CODEBERG_HOST" '.hosts[$h].token // empty' \
    "${XDG_DATA_HOME:-$HOME/.local/share}/forgejo-cli/keys.json")
  [[ -n $CODEBERG_TOKEN ]] || { echo "codeberg: no token; set CODEBERG_TOKEN or run 'fj auth login'" >&2; return 1; }
}

cb_watching() {
  # Prints "<subscribed> <ignored>"; the API returns 404 when not watching.
  local out rc
  out=$(cb GET "repos/$1/subscription" 2>&1) && rc=0 || rc=$?
  if ((rc == 0)); then
    jqv '"\(.subscribed) \(.ignored)"' "$out"
  elif ((rc == 4)); then
    echo "false false"
  else
    echo "$out"
    return 1
  fi
}

codeberg_repo() {
  local r=$1 repo branch prot rc
  repo=$(jq -r .full_name <<<"$r")
  branch=$(jq -r .default_branch <<<"$r")
  echo "codeberg: $repo"

  # Default notifications: watching, which Forgejo sets on repos you create.
  setting "notifications: watching (Forgejo default)" "true false" \
    cb_watching "$repo" -- \
    cb PUT "repos/$repo/subscription"

  prot=$(cb GET "repos/$repo/branch_protections/$(urlenc "$branch")" 2>&1) && rc=0 || rc=$?
  if ((rc == 0)); then
    # Forgejo always rejects force pushes and deletion on a protected branch.
    setting "$branch: protected, signed commits not required (admins too)" "false true" \
      jqv '"\(.require_signed_commits) \(.apply_to_admins)"' "$prot" -- \
      cb PATCH "repos/$repo/branch_protections/$(urlenc "$branch")" \
        '{"require_signed_commits":false,"apply_to_admins":true}'
  elif ((rc == 4)); then
    change "protect $branch (no force push/deletion, signed commits not required)" \
      cb POST "repos/$repo/branch_protections" \
        "$(jq -cn --arg b "$branch" '{rule_name: $b, enable_push: true,
            require_signed_commits: false, apply_to_admins: true}')"
  else
    fail "get branch protection: $prot"
  fi

  setting "delete branch on merge (default)" true \
    jqv .default_delete_branch_after_merge "$r" -- \
    cb PATCH "repos/$repo" '{"default_delete_branch_after_merge":true}'
}

run_codeberg() {
  local owner kind page batch r
  codeberg_token || { ERRORS=$((ERRORS + 1)); return 0; }
  for owner in "${OWNERS[@]}"; do
    if cb GET "orgs/$(urlenc "$owner")" >/dev/null 2>&1; then kind=orgs; else kind=users; fi
    page=1
    while :; do
      if ! batch=$(cb GET "$kind/$(urlenc "$owner")/repos?limit=50&page=$page" 2>&1); then
        fail "codeberg: list repos for $owner: $batch"
        break
      fi
      [[ $(jq length <<<"$batch") -gt 0 ]] || break
      while read -r -u 3 r; do
        if [[ $(jq -r '.archived or .fork or .mirror or .empty' <<<"$r") == true ]]; then
          echo "codeberg: $(jq -r .full_name <<<"$r")"; skip "archived, fork, mirror or empty"
        else
          codeberg_repo "$r"
        fi
      done 3< <(jq -c '.[]' <<<"$batch")
      page=$((page + 1))
    done
  done
}

# --- main --------------------------------------------------------------------
for platform in "${PLATFORMS[@]}"; do
  "run_$platform"
done

echo
if $APPLY; then
  echo "done: $CHANGES change(s) attempted, $ERRORS error(s)"
else
  echo "dry run: $CHANGES change(s) needed, $ERRORS error(s). Re-run with --apply to make them."
fi
((ERRORS == 0))
