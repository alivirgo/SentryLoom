package org.sentryloom.android;

import android.content.Context;
import android.os.Build;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class EnrollmentManager {
    private final EndpointState state;

    EnrollmentManager(Context context) {
        state = new EndpointState(context);
    }

    String request(String serverUrl, String fingerprint) throws Exception {
        String pin = PinnedHqClient.normalizeFingerprint(fingerprint);
        PinnedHqClient probe = pin.isEmpty()
                ? PinnedHqClient.firstUseProbe(serverUrl)
                : new PinnedHqClient(serverUrl, pin);
        PinnedHqClient.Response identity = probe.get("/api/v1/hq", null, null);
        String learnedPin = identity.fingerprint;
        if (!pin.isEmpty() && !pin.equals(learnedPin)) {
            throw new IllegalStateException("HQ certificate fingerprint mismatch");
        }
        String advertised = PinnedHqClient.normalizeFingerprint(
                identity.body.optString("fingerprint256")
        );
        if (!advertised.equals(learnedPin)) {
            throw new IllegalStateException("HQ advertised a different certificate identity");
        }
        PinnedHqClient client = new PinnedHqClient(serverUrl, learnedPin);
        state.setLastServerUrl(serverUrl.replaceAll("/+$", ""));
        String code = EndpointState.verificationCode();
        byte[] challengeBytes = new byte[32];
        new SecureRandom().nextBytes(challengeBytes);
        String challenge = PinnedHqClient.base64Url(challengeBytes);
        JSONObject device = new JSONObject()
                .put("installationId", state.installationId())
                .put("name", Build.MODEL)
                .put("hostname", Build.DEVICE)
                .put("platform", "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")")
                .put("appVersion", EndpointState.VERSION);
        JSONObject response = client.post(
                "/api/v1/enrollment-requests",
                new JSONObject().put("device", device).put("verificationChallenge", challenge),
                null
        ).body;
        state.setPending(new JSONObject()
                .put("serverUrl", serverUrl.replaceAll("/+$", ""))
                .put("fingerprint256", learnedPin)
                .put("hqName", response.optString("hqName", identity.body.optString("name", "SentryLoom HQ")))
                .put("requestId", response.getString("requestId"))
                .put("requestSecret", response.getString("requestSecret"))
                .put("requestedAt", response.optString("requestedAt"))
                .put("verificationCode", code)
                .put("verificationChallenge", challenge));
        state.setStatus("Waiting for HQ approval · code " + code);
        return code;
    }

    boolean poll() throws Exception {
        JSONObject pending = state.pending();
        if (pending == null) return false;
        PinnedHqClient client = new PinnedHqClient(
                pending.getString("serverUrl"), pending.getString("fingerprint256")
        );
        JSONObject response = client.get(
                "/api/v1/enrollment-requests/" + pending.getString("requestId"),
                null,
                pending.getString("requestSecret")
        ).body;
        String status = response.optString("status");
        if ("rejected".equals(status)) {
            state.setStatus("Enrollment rejected by HQ");
            return false;
        }
        if (!"approved".equals(status)) return false;
        String expected = proof(
                pending.getString("verificationCode"),
                pending.getString("requestId"),
                pending.getString("verificationChallenge")
        );
        if (!constantTime(expected, response.optString("verificationProof"))) {
            state.setStatus("Enrollment verification failed; submit a new request");
            throw new SecurityException("HQ approval used the wrong verification code");
        }
        state.setCredentials(new JSONObject()
                .put("serverUrl", pending.getString("serverUrl"))
                .put("fingerprint256", pending.getString("fingerprint256"))
                .put("hqName", response.optString("hqName", pending.optString("hqName")))
                .put("deviceId", response.getString("deviceId"))
                .put("token", response.getString("token"))
                .put("enrolledAt", response.getString("enrolledAt")));
        state.setStatus("Enrolled and connected");
        return true;
    }

    private static String proof(String code, String requestId, String challenge) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(code.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return PinnedHqClient.base64Url(hmac.doFinal(
                ("sentryloom-enrollment-v1\0" + requestId + "\0" + challenge)
                        .getBytes(StandardCharsets.UTF_8)
        ));
    }

    private static boolean constantTime(String expected, String supplied) {
        byte[] left = expected.getBytes(StandardCharsets.UTF_8);
        byte[] right = supplied.getBytes(StandardCharsets.UTF_8);
        return left.length == right.length && java.security.MessageDigest.isEqual(left, right);
    }
}
