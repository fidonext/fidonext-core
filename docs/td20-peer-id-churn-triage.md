# TD-20 — peer_id churn after `am force-stop`: triage

**Date:** 2026-04-19  
**Triaged by:** `security-crypto-engineer`  
**Status:** inconclusive — evidence points at an Android service-init race AND/OR a QA-harness data wipe; need one 5-minute re-run with `ls filesDir` to discriminate.

## 1. Finding (one-liner)

**Inconclusive on its own, but there is at minimum one real defect uncovered:** a concurrent-init race on `fidonext.profile.json` visible in Bob's first-run logcat. The race alone does not fully explain the post-force-stop churn, so either (a) the first-run race has a path where nothing is persisted to disk, or (b) the emulator harness is wiping `filesDir` out-of-band (e.g. `pm clear`, a reinstall, or an AVD snapshot reset).

The persistence logic in Rust is correct (three seeds in one JSON, atomic temp+rename, 0600 perms). The bug is not "we forget to persist the libp2p transport key" — all three seeds (account, libp2p-transport, signal-identity) plus `device_id` are in the same file. We are **not** in scenario (3) from the prompt (split identity); we're either in (1) with a twist, or (4).

## 2. Evidence

### 2.1 Logcat (`qa-artifacts/2026-04-20T2240Z-td0506-wiring/logcat-bob.txt`)

```
line 6:  22:39:09.059 D Initializing node with 2 bootstrap peers   (pid 3297)
line 8:  22:39:09.329 D Initializing node with 2 bootstrap peers   (pid 3297)   <-- second concurrent init
line 10: 22:39:09.533 E Failed to load/create identity profile     (pid 3297)   <-- one of the two errored
line 11: 22:39:09.841 I Node initialized successfully … Jh8dB…aKgk deviceId=dev-46e0eb8a  (pid 3297)

... (~5 min of traffic, then am force-stop) ...

line 241: 22:44:14.486 D Initializing node with 2 bootstrap peers  (pid 5528)
line 243: 22:44:14.600 I Node initialized successfully … GUkf…vN5k deviceId=dev-1a168464  (pid 5528)

line 703: 22:54:57.825 D Initializing node with 2 bootstrap peers  (pid 6825)
line 704: 22:54:57.849 I Node initialized successfully … GUkf…vN5k deviceId=dev-1a168464  (pid 6825)
```

Key observations:
- Pid 3297 had TWO near-simultaneous `Initializing node` calls; one of them errored at `cabi_identity_load_or_create`.
- Pid 5528 (after force-stop) produced a **completely different** accountId, deviceId, AND libp2p peer_id. All three seeds rotated. This is consistent with `load_or_create_profile` taking the `create_profile` branch, i.e. the file did not exist at restart.
- Pid 6825 (a later manual relaunch) REUSED pid 5528's identity. So persistence does work; it's specifically the pid-3297 → pid-5528 transition that lost the file.

### 2.2 Android service init path

`fidonext_android/app/src/main/java/com/fidonext/messenger/service/Libp2pService.kt:389`:

```kotlin
val profile = java.io.File(filesDir, "fidonext.profile.json").absolutePath
profilePath = profile
val identity = Libp2pNative.cabiIdentityLoadOrCreate(profile)
```

Path is stable (`filesDir` = `/data/user/0/com.fidonext.messenger/files/`), identical across init calls. CE storage (manifest has no `android:directBootAware`), so the path is the same across any unlocked state.

`Libp2pService.initializeNode()` at line 378 is callable from AIDL binder threads. Its only concurrency guard is `if (nodeHandle != 0L) return true` (line 380) — no monitor, no `@Synchronized`. Two callers: `PeerListViewModel.initializeNode()` (PeerListViewModel.kt:358, `Dispatchers.IO`) and `ChatViewModel.initializeNode()` (ChatViewModel.kt:77, `Dispatchers.IO`). Both bind on their own lifecycle and both call through. The logcat confirms both ran (two "Initializing node" lines 270ms apart).

### 2.3 Rust persistence path

`fidonext-core/c-abi-libp2p/src/e2ee/mod.rs:228-298` — `load_or_create_profile` / `create_profile`:
- Single JSON (`StoredIdentityProfile`) holds `account_seed_b64`, `libp2p_seed_b64`, `signal_identity_seed_b64`, `device_id`.
- `persist_profile` (line 300) writes to a **deterministic** temp path (line 382: `fidonext.profile.json.tmp`), `fsync`s, then `fs::rename`. Under a concurrent call the two writers share the same temp path, with all the usual races:
  - Second `O_CREAT|O_TRUNC` on the temp file re-truncates first writer's in-flight bytes (same inode).
  - First `fs::rename(tmp, path)` succeeds; second `fs::rename` observes `ENOENT` and errors.
  - If BOTH writers somehow rename to the wrong place or both get ENOENT (Android sdcardfs / fusefs has odd semantics under contention), disk can end up with nothing at `path`.
- On `create_profile` success, the in-memory `IdentityProfile` is returned to the caller regardless of whether the file was flushed to the Android-visible inode. So a partial write followed by a race-induced `persist_profile` error is caught by `?` and the whole call errors — but the NON-erroring sibling call can return an IdentityProfile whose seeds are real in the process but whose on-disk persistence was clobbered by the second writer's truncate-then-ENOENT sequence.

### 2.4 AndroidManifest

`AndroidManifest.xml:10-36` — `android:allowBackup="true"`, no `BackupAgent`, no `android:fullBackupContent`. Default Auto-Backup is benign for force-stop; it does NOT wipe filesDir.

### 2.5 APK install path unchanged

Between pid 3297, 5528, 6825 the `nativeloader` lines show identical install hash `~~L6CTdfYOD1aC2V4xtpcP_Q==/com.fidonext.messenger-q1pfkk6MDapJVw4rPU3MdA==`. So **it was not a reinstall**. A `pm clear` or AVD snapshot reset cannot be distinguished from this evidence.

## 3. Root cause hypotheses (ranked)

1. **H1 (high, confirmed defect regardless of TD-20):** Concurrent init race in `Libp2pService.initializeNode`. Two ViewModels launch-bind and both call into native `cabi_identity_load_or_create`. Deterministic temp path (`fidonext.profile.json.tmp`) plus non-atomic `O_CREAT|O_TRUNC` + later `fs::rename` is a classic footgun. It IS causing the "Failed to load/create identity profile" error on first run. Whether it can actually leave the file absent on disk is FS-dependent but plausible on ext4 with lazy allocation under heavy rename pressure.
2. **H2 (medium):** QA harness artifact. Some test-runner wrappers around `am force-stop` also chain `adb shell pm clear` or snapshot-restore the AVD. env.txt does not document the restart recipe. Would cleanly explain "all three seeds rotated" without any code bug.
3. **H3 (low):** Direct Boot / CE storage transition. Ruled out — manifest uses default (CE), and filesDir path is stable once the user is unlocked, which is the only state in which the service can run at all.
4. **H4 (very low):** A silent Android Auto-Backup restore fired between force-stop and next launch. Requires Google Play Services and a backup set; emulator normally doesn't do this automatically. Ignorable.

## 4. Blast radius

Severity: **HIGH** (blocker for "first real-user release" milestone, matches ROADMAP triage).

If the libp2p peer_id rotates on every `am force-stop` (or on every OS-driven process kill — low-memory, battery, Doze):
- **Contacts break.** Remote peers still have the stale `peer_id` in their local `PeerRepository`; they can no longer route to the user.
- **Session state is garbage.** All Signal/libsignal sessions are keyed by peer_id; they become unusable and new X3DH must be done, with prekey bundles published under the NEW peer_id (old bundles are orphaned in DHT).
- **Presence is broken.** TD-07/TD-09 presence logic keys by peer_id. Peers appear permanently offline.
- **DHT pollution.** Every restart publishes fresh directory+prekey records under a new key; old records live until DHT TTL. Correlation attack surface (observer can enumerate all past identities of one user).
- **Account identity also rotates** (not just libp2p) — MORE damaging than the split scenario. If account_id changes, any future nickname-registry (TD-15) claim is lost.

## 5. Owner(s) for the fix

- **`android-engineer`** — **primary**. Must serialize `Libp2pService.initializeNode` (monitor / `@Synchronized` / AtomicRef state machine) so it is called exactly once per service lifetime, regardless of how many ViewModels bind. This alone resolves H1.
- **`rust-p2p-engineer`** — **defense-in-depth**. Even a single-threaded caller benefits from randomized temp paths (`fidonext.profile.json.<pid>.<rand>.tmp`) and better error paths; but this is secondary — Rust was never meant to be called concurrently on the same profile_path.
- **`e2e-qa-engineer`** — **must re-run**. Before/after `am force-stop`, capture `adb shell run-as com.fidonext.messenger ls -la files/` and include `stat` timestamps in the artifact. Also document the EXACT restart recipe in `env.txt` for every future run. This distinguishes H1 vs H2.

## 6. Recommended fix shape (do NOT implement yet)

### A. Android (primary)

In `Libp2pService.kt`, gate `initializeNode(bootstrapPeers: Array<String>)` with a coroutine `Mutex` or plain `synchronized(initLock)` so at most one call executes the load-or-create + `cabi_node_new` block at a time. The existing `if (nodeHandle != 0L) return true` fast-path stays but under the lock. Pseudocode:

```kotlin
private val initLock = Mutex()

private suspend fun initializeNode(bootstrap: Array<String>): Boolean = initLock.withLock {
    if (nodeHandle != 0L) return@withLock true
    // existing body
}
```

Alternative: make initialization happen once in `Service.onCreate` (service-scoped state machine) and expose a suspend-until-ready API to ViewModels; ViewModels do NOT trigger init at bind-time. This is cleaner but larger.

### B. Rust (defense-in-depth)

Two low-risk tweaks in `fidonext-core/c-abi-libp2p/src/e2ee/mod.rs`:
1. Make `temporary_path` include a random suffix (e.g. `fidonext.profile.json.<hex-rand-8>.tmp`) so concurrent writers don't collide on the SAME temp inode.
2. Before entering `create_profile`, acquire an advisory `flock` on the profile directory (or use `OpenOptions::create_new(true)` on the final path as an atomic "first writer wins"; subsequent writers loop back to `load_profile`).

### C. QA re-run

`e2e-qa-engineer` to reproduce with the following additions captured in `env.txt`:
- `adb shell run-as com.fidonext.messenger ls -la files/` immediately before `am force-stop`.
- The exact `am force-stop` command executed.
- `adb shell run-as com.fidonext.messenger ls -la files/` immediately after force-stop, before relaunch.
- Hash of `fidonext.profile.json` before force-stop, hash after relaunch — must be identical if persistence works.
- Bob ONLY launches MainActivity (no ChatActivity) on first run, to test whether removing the second ViewModel also removes the race. If it does: H1 confirmed. If peer_id still rotates post-force-stop even with only one init call: H2 confirmed.

## 7. Security note

If H1 is the sole cause, user-visible harm is "identity rotates on ~1% of cold-starts where both activities land fast enough to race". Bad but not catastrophic.

If H1 + H2 combine (harness wipes + race), real-world users on memory-pressured devices might see identity rotation regularly when Android kills the process under memory pressure and re-launches it. That IS catastrophic and is the scenario we must prevent before any public beta.

Either way, landing the Android-side mutex is a **hard prerequisite** for the first real-user release. The Rust defense-in-depth is nice-to-have.

