# SentryLoom Android client

The Android client is a native, dependency-free Java application for Android
8.0 (API 26) and newer. It uses the same certificate-pinned enrollment,
telemetry, and allowlisted-command protocol as desktop endpoints.

## Build

Requirements:

- JDK 17 or newer
- Android SDK Platform 36 and Build Tools 36.0.0
- internet access on the first build so the Gradle wrapper can resolve Android
  Gradle Plugin 9.2.1

```text
cd clients/android
./gradlew assembleDebug
```

The installable debug APK is written to
`app/build/outputs/apk/debug/app-debug.apk`. For production, configure an
organization-controlled release signing key and build `assembleRelease`.
Never ship the shared Android debug certificate as a production identity.

## Enrollment

1. Open SentryLoom HQ and note its HTTPS address. The SHA-256 certificate
   fingerprint is optional: when omitted, the app uses trust-on-first-use and
   permanently pins the certificate presented by that first connection.
2. Install and open the APK.
3. Enter the HQ URL and, optionally, its fingerprint, then tap
   **Request HQ enrollment**.
4. Enter the displayed six-digit code in the HQ approval dialog.
5. Enable background protection. Android displays a persistent notification
   while management is active.

Credentials are AES-256-GCM encrypted with a non-exportable Android Keystore
key. HQ TLS is accepted only when the leaf-certificate SHA-256 fingerprint
matches the enrolled pin.

## Management levels

Normal installation provides hardware, OS/build, security-patch, battery,
storage, memory, network/private-DNS/proxy, application, signing-certificate,
permission-risk, usage, ownership, and runtime telemetry. The persistent
protection service monitors package and network changes, evaluates device
posture, keeps a tamper-evident local security-event chain, and reports scan
and command history to HQ. It can hash installed APKs, verify signer
fingerprints, run on-demand posture checks, and refresh HQ telemetry.

Device Administrator is user-approved and adds remote device lock.

Device Owner or Profile Owner is an Android Enterprise provisioning state.
Device Owner adds remote reboot, camera, screen-capture, unknown-source,
safe-boot, factory-reset, USB-data-signaling, and Bluetooth-sharing policy
controls. On a factory-reset test device with no configured accounts:

```text
adb shell dpm set-device-owner org.sentryloom.android/.SentryDeviceAdminReceiver
```

Production Device Owner provisioning should use Android Enterprise QR, zero
touch, or another supported enterprise enrollment flow.

## Android platform boundaries

- Scoped storage prevents silent background access to every personal file.
  This client scans installed APK files that Android exposes to it. A future
  user-selected document scan can use the Storage Access Framework.
- `QUERY_ALL_PACKAGES` is declared because complete application inventory is
  a core enterprise security function. Public Play distribution is subject to
  Google Play's restricted-permission review; direct enterprise deployment
  does not remove the need for organizational consent and policy.
- Remote reboot is available only in Device Owner mode.
- No arbitrary shell, command string, package installation, camera,
  microphone, message, or credential collection API exists.
- Remote wipe is intentionally not implemented. Destructive deprovisioning
  belongs in a separately authorized enterprise workflow with stronger
  safeguards than the current command queue.
