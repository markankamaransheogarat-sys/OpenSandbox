#!/usr/bin/env bash
# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# verify/vault.sh — credential-vault lifecycle over the server relay (OSEP-0022)
#
# Coverage (all assertions on the live egress sidecar via the fastlet
# Actions channel; log markers are read from the pool's egress containers):
#
#   1. Subject registration: the sandbox is created with a create-carried
#      default-deny egress policy (allow ext.test) — a policy-less create
#      produces no egress binding at all, so the subject would never
#      register. The verify waits for the egress log marker
#      "subject s-<uid>: data-plane-ready, policy active".
#   2. Vault create over the server relay: POST
#      /sandboxes/{id}/credential-vault (inline credential `tok` + an
#      apiKey binding for host ext.test) must ack with a numeric revision.
#   3. Create-only invariant: a duplicate POST must be rejected with 409.
#   4. Pause/resume vault transfer: pause exports the vault into the
#      checkpoint bundle ("vault exported to snapshot bundle" marker);
#      the pause's REMOVE_BINDING purges the subject, so on resume the
#      import lands through the unregistered branch and the file reloads
#      at the SET_BINDING replay ("vault reloaded from file" marker). The
#      relay GET must report the SAME revision across the round trip.
#   5. Egress crash recovery: the egress process is pkilled in every pool
#      pod; when the containers come back (fresh instanceId -> SET_BINDING
#      replay -> vault file reload by incarnation) the relay must still
#      report the original revision. Skipped on pods without pkill.
#   6. Delete/re-create: DELETE -> GET 404; a fresh POST starts again at
#      revision 1.
#   7. Cleanup: kill the sandbox and wait until GET 404s.
#
# Housekeeping: the artifact store is pruned at entry — stale checkpoint /
# template sets are removed, the baseline golden template set and the
# indexes pointing into it are preserved.
#
# Runs as part of `integration.sh up` (the entry chains every verify
# script) or standalone against a live stack from `env.sh up`.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

# --- stage: vault lifecycle (OSEP-0022: egress-held vault over the relay) --------

# Status-code-returning variant of server_api for negative-path assertions
# (curl -f hides the status).
server_api_status() { # method path [json-body]
	local method="$1" path="$2" body="${3:-}" out
	if [[ -n "$body" ]]; then
		out="$(curl -sS -m 60 -X "$method" -H "OPEN-SANDBOX-API-KEY: $SERVER_API_KEY" \
			-H "Content-Type: application/json" -d "$body" -w '\n%{http_code}' "$SERVER_URL$path" 2>/dev/null)"
	else
		out="$(curl -sS -m 60 -X "$method" -H "OPEN-SANDBOX-API-KEY: $SERVER_API_KEY" \
			-w '\n%{http_code}' "$SERVER_URL$path" 2>/dev/null)"
	fi
	printf '%s' "${out##*$'\n'}"
}

# The vault stage's sandbox must ride the subject-scoped egress log markers
# (export/import/registration), so every log assertion goes through this.
# Also check --previous container logs in case a container restarted before
# the log poll observed an earlier marker.
vault_log_contains() { # <fixed-substring>
	local pod
	if kubectl -n "$RESOURCE_NS" logs -l app=sandbox-fastlet -c egress --tail=800 2>/dev/null \
		| grep -qF "$1"; then
		return 0
	fi
	for pod in $(pool_pods); do
		if kubectl -n "$RESOURCE_NS" logs "$pod" -c egress --previous --tail=800 2>/dev/null \
			| grep -qF "$1"; then
			return 0
		fi
	done
	return 1
}

vault_revision_is() { # <expected-revision>
	local out
	out="$(server_api GET "/sandboxes/$VERIFY_ID/credential-vault" 2>/dev/null)" || return 1
	[[ "$(printf '%s' "$out" | jq -r '.revision // empty')" == "$1" ]]
}

vault_lifecycle_verify() {
	local created vault_body ack rev sandbox_uid
	# The pause here publishes a checkpoint set (vault + policy bundles):
	# drop stale ones from earlier runs before this verify adds its own.
	prune_artifact_store
	log "verify (vault): creating a sandbox via the opensandbox CLI (templateId=$TEMPLATE_ID)"
	# The policy rides the create: a policy-less create produces no egress
	# binding at all, so the subject would never register.
	jq -n '{defaultAction: "deny", egress: [{action: "allow", target: "ext.test"}]}' \
		> "$GEN_DIR/vault-policy.json"
	created="$(osb_api sandbox create --template "$TEMPLATE_ID" --timeout 1h \
		--metadata origin=fast-sandbox-env-vault \
		--network-policy-file "$GEN_DIR/vault-policy.json" \
		--skip-health-check -o json 2>/dev/null)" \
		|| fail "vault verify: sandbox create failed"
	VERIFY_ID="$(printf '%s' "$created" | jq -r '.id')"
	wait_for "vault sandbox Running" 150 sandbox_running
	sandbox_uid="$(kubectl -n "$RESOURCE_NS" get sandbox "$VERIFY_ID" -o jsonpath='{.metadata.uid}' 2>/dev/null)"
	[[ -n "$sandbox_uid" ]] || fail "vault verify: sandbox CR carried no uid"
	# Registered and activated before the vault POST, else the relay 404s.
	# (The "(state=active)" re-delivery only follows a policy UPDATE; a
	# create-carried policy activates without it.)
	wait_for "vault subject registered on egress" 120 \
		vault_log_contains "subject s-$sandbox_uid: data-plane-ready, policy active"

	# 1) create-only: ack carries the revision; duplicate POST is 409.
	vault_body="$(jq -n '{credentials: [{name: "tok", source: {type: "inline", value: "sekrit-vault-e2e"}}], bindings: [{name: "ext", match: {hosts: ["ext.test"]}, auth: {type: "apiKey", name: "X-Api-Key", credential: "tok"}}]}')"
	ack="$(server_api POST "/sandboxes/$VERIFY_ID/credential-vault" "$vault_body")" \
		|| fail "vault verify: POST credential-vault failed"
	rev="$(printf '%s' "$ack" | jq -r '.revision // empty')"
	[[ "$rev" =~ ^[0-9]+$ ]] || fail "vault verify: create ack carried no revision: $(printf '%s' "$ack" | head -c 200)"
	pass "vault created over the relay (ack revision $rev)"
	if server_api POST "/sandboxes/$VERIFY_ID/credential-vault" "$vault_body" >/dev/null 2>&1; then
		fail "vault verify: duplicate POST succeeded (create-only must 409)"
	fi
	[[ "$(server_api_status POST "/sandboxes/$VERIFY_ID/credential-vault" "$vault_body")" == "409" ]] \
		|| fail "vault verify: duplicate POST was not 409"
	pass "duplicate POST rejected (create-only 409)"

	# 2) pause/resume carries the real vault: export -> bundle -> import,
	#    with the relay GET reporting the same revision.
	osb_api sandbox pause "$VERIFY_ID" >/dev/null 2>&1 || fail "vault verify: pause failed"
	wait_for "vault sandbox Paused (checkpoint durable)" 240 sandbox_paused
	wait_for "vault exported into the checkpoint bundle" 120 \
		vault_log_contains "subject s-$sandbox_uid: vault exported to snapshot bundle"
	pass "pause exported the vault bundle (subject sealed)"
	osb_api sandbox resume "$VERIFY_ID" --skip-health-check >/dev/null 2>&1 || fail "vault verify: resume failed"
	wait_for "vault sandbox Running (restored)" 240 sandbox_running
	# The pause's REMOVE_BINDING purges the subject, so the restore import
	# lands through the unregistered branch and the file reloads at the
	# SET_BINDING replay (the reload line carries the restored revision).
	wait_for "vault bundle reloaded at re-registration" 120 \
		vault_log_contains "subject s-$sandbox_uid: vault reloaded from file"
	wait_for "vault revision preserved across pause/resume" 120 vault_revision_is "$rev"
	pass "vault survived pause/resume (revision $rev preserved)"

	# 3) egress-restart recovery: crash the worker (fresh instanceId ->
	#    SET_BINDING replay -> vault file reload by incarnation).
	local pod restarted=0
	for pod in $(pool_pods); do
		if kubectl -n "$RESOURCE_NS" exec "$pod" -c egress -- sh -c 'command -v pkill >/dev/null' 2>/dev/null; then
			kubectl -n "$RESOURCE_NS" exec "$pod" -c egress -- pkill -f '/opt/opensandbox-egress/egress' >/dev/null 2>&1 || true
			restarted=1
		else
			log "verify (vault): egress restart skipped on ${pod##*/} (pkill unavailable)"
		fi
	done
	if [[ "$restarted" == 1 ]]; then
		wait_for "pool egress containers back up" 180 egress_containers_ready
		wait_for "vault reloaded after egress restart" 240 vault_revision_is "$rev"
		pass "vault reloaded after egress restart (revision $rev preserved)"
	fi

	# 4) delete + re-create.
	server_api DELETE "/sandboxes/$VERIFY_ID/credential-vault" >/dev/null \
		|| fail "vault verify: DELETE failed"
	[[ "$(server_api_status GET "/sandboxes/$VERIFY_ID/credential-vault")" == "404" ]] \
		|| fail "vault verify: GET after DELETE was not 404"
	pass "vault deleted (GET 404)"
	ack="$(server_api POST "/sandboxes/$VERIFY_ID/credential-vault" "$vault_body")" \
		|| fail "vault verify: re-create after DELETE failed"
	rev="$(printf '%s' "$ack" | jq -r '.revision // empty')"
	[[ "$rev" == "1" ]] || fail "vault verify: fresh vault revision is $rev, expected 1"
	pass "vault re-created (fresh revision $rev)"

	osb_api sandbox kill "$VERIFY_ID" >/dev/null 2>&1 \
		|| log "verify cleanup: kill failed; remove $VERIFY_ID manually"
	wait_for "vault sandbox deleted" 120 verify_sandbox_gone
}

# --- standalone entry ----------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	resolve_osb
	require_template_id
	trap 'on_error vault-verify' ERR
	run_stage "vault lifecycle verify (CLI -> relay -> egress-held vault)" vault_lifecycle_verify
fi
