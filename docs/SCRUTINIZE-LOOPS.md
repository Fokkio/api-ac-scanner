# Outsider review — 5 loops

1. Intent/isolation: หก version แยก folder, version identifiers ตรงกัน, V2.5 ไม่ถูกใช้เป็น target เขียน
2. Security/failure paths: แก้ cross-origin discovery, DEL/header validation และบังคับ cleanup แม้ POST timeout
3. Correctness/edge cases: แก้ DELETE 404 หลัง POST 201 ไม่ให้ถือว่าสำเร็จ และ reject incomplete policy ก่อน network
4. Packaging/code review: ทั้งหก images build/test ผ่าน, Compose configs ผ่าน, Semgrep 12 rules valid; TypeScript A, Python B
5. Final trace: cumulative UI-to-report E2E ผ่าน Discovery, Source, Deep, Matrix, Verification, Correlation และ Mutation cleanup; secrets ไม่อยู่ใน state

ทางเลือกที่เล็กกว่าคือ CLI matrix runner ซึ่งลด UI/session surface แต่ไม่ตรงเป้าหมาย PageSpeed-style local UI จึงคง web orchestrator แบบ single-node

Verdict: `ship for authorized local lab`; ไม่ใช่ production SaaS และไม่ควรตีความ no finding ว่าไม่มีช่องโหว่

## V3.2 outsider review — 5 loops

1. Contract/default deny: remote mutation is disabled by default, requires an exact HTTPS port-443 origin and uses a separate confirmation phrase.
2. Web boundary/legacy state: verified method is persisted; old remote records must re-verify; legacy local records still follow the current local allowlist.
3. Scanner boundary/order: target must be an exact origin; config and live proof are checked before login or state-changing steps; all resource paths remain under `/__ac_test__/`.
4. Cleanup/upgrade behavior: existing create-cleanup and reverse-cleanup semantics are reused; Compose project identity remains stable to avoid orphaning the prior stack.
5. Trace/runtime: Web proof propagation, Scanner serialization, stale-proof rejection, all five HTTP methods, adapter contracts and PostgreSQL cleanup are covered; authorized remote success is deliberately left unclaimed.

Simpler-alternative decision: reuse the existing guarded engines and add one exact-origin proof gate. A second scanner service or arbitrary production-path mode would add operational and security surface without improving the stated staging-only goal.

Verdict: `ship for authorized staging with guardrails`; remote production testing is not automatically safe merely because domain ownership is claimed. The target still needs a dedicated disposable namespace, test data, test identities and independently observable cleanup.

## Local no-login outsider review — 8 loops

1. Intent/scope: removed only the Scanner UI login and obsolete administrator configuration; kept session-backed CSRF because local browser requests still need mutation protection.
2. Request boundary: moved multipart CSRF validation before upload writes, added same-origin checks and restricted accepted Host values to loopback names.
3. Persistence/upgrade: migrated state v1 to v2 without legacy `ownerScope`, preserved completed reports and made temporary state-file cleanup failure-safe.
4. Operations/errors: direct start now defaults to `127.0.0.1`; Compose explicitly uses the container bind address, maps the host to loopback only and handles known upload/body errors with specific responses.
5. Final trace: direct dashboard access, removed `/login`, Host/origin/CSRF rejection, valid CSRF mutation, upload cleanup, launcher migration, image tests and two-container health all pass.
6. Maintainability pass: split upload routes and environment migration from oversized route/launcher files; all in-scope files and functions now meet the selected standards.
7. Drift pass: centralized launcher action metadata and dispatch to remove repeated switches and shotgun edits; added unique-name/key regressions.
8. Clean pass: both spec and standards reviewers reported no actionable in-scope findings after a fresh Docker build and runtime smoke test.

Simpler-alternative decision: a no-op or auto-login layer would preserve dead credential/session concepts without adding protection. The smaller safe design is direct local access plus strict loopback publishing, Host/origin validation and CSRF.

Verdict: `ship for local-only Docker use`; every local process or user able to reach `127.0.0.1:3000` is inside the operator trust boundary. Do not expose this build to a LAN or the public Internet.
