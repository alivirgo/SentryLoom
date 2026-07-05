# Client/HQ connection resilience

This plan is implemented by the endpoint connector, Windows scheduled tasks, and
the HQ operations-alert feed.

## Covered lifecycle cases

| Condition | Client behavior | HQ behavior |
| --- | --- | --- |
| Network cable/Wi-Fi/VPN is lost | Keeps local protection active, marks HQ reconnecting/offline, retries with bounded exponential backoff | Marks the endpoint offline after 60 seconds without telemetry |
| Network returns | Retries within 30 seconds at worst and immediately resumes telemetry when successful | Clears the offline alert when telemetry returns |
| Sleep or hibernate | Detects the long timer gap on resume, discards the old retry delay, and sends fresh telemetry immediately | Receives a new heartbeat without requiring an app restart |
| Background client exits unexpectedly | Windows Task Scheduler restarts it every minute, without a three-retry limit | Shows an offline alert until the restarted client checks in |
| A different Windows user opens the GUI | Reads the same machine-wide configuration, device identity, enrollment, and connector state | Continues tracking one unchanged endpoint identity |
| Dashboard owns no connector lease | Reads the background connector's shared status and retries lease acquisition if the owner exits | Continues to receive one telemetry stream per endpoint |
| Server is unavailable | Client raises one actionable Windows notification; repeated retries are deduplicated | HQ dashboard visibly reports its own API connection loss |
| Connection is restored | Client emits and displays a recovery notification | Dashboard updates online state and clears the availability alert |
| Threat or monitoring failure | Client emits a Windows notification and dashboard activity event | HQ alert feed shows detections, endpoint failures, and failed remote commands |
| Operator clicks Find HQ | Discovers servers without changing the active HQ, credential, device ID, or telemetry connector | Existing endpoint remains online |
| Setup requests a different HQ | After the new target accepts the enrollment request, the client removes the prior encrypted credential and stale connector state, then polls the new approval | The selected HQ provisions the approved endpoint and begins receiving telemetry |

The interactive tray process owns a notification-area status icon. It is
green while the latest connector heartbeat reports HQ online and red when HQ is
unreachable or the state is stale. Double-clicking the icon opens the console;
its menu also opens the Activity page where bounded background stdout/stderr,
scan events, and remote-command results can be loaded without exposing a
console window.

## Timing and anti-noise policy

- Normal command polling: 1.5 seconds.
- Normal telemetry: every 2 seconds.
- Offline status at HQ: 60 seconds without telemetry.
- Retry backoff: 1.5 seconds up to 30 seconds.
- Client outage notification: after two consecutive connection failures.
- Resident protection startup: Windows startup under `SYSTEM`; independent of
  installer and desktop-user accounts.
- Repeated endpoint notifications: deduplicated for five minutes.

## Operational verification

1. Enroll a client and confirm it is online in HQ.
2. Disconnect networking for more than 60 seconds and confirm both client and HQ alerts.
3. Reconnect networking and confirm telemetry and commands recover without restarting either app.
4. Sleep and resume the endpoint; confirm `system.resume-detected` followed by a fresh HQ contact.
5. End the realtime protection process and confirm Task Scheduler restarts it within one minute.
6. Queue a scan after each recovery case and confirm its result reaches HQ.
