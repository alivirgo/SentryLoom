package org.sentryloom.android;

import android.util.Base64;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

final class PinnedHqClient {
    static final class Response {
        final JSONObject body;
        final String fingerprint;

        Response(JSONObject body, String fingerprint) {
            this.body = body;
            this.fingerprint = fingerprint;
        }
    }

    private final String baseUrl;
    private final String expectedFingerprint;
    private final boolean trustOnFirstUse;

    PinnedHqClient(String baseUrl, String fingerprint) {
        this(baseUrl, fingerprint, false);
    }

    private PinnedHqClient(String baseUrl, String fingerprint, boolean trustOnFirstUse) {
        this.baseUrl = normalizeUrl(baseUrl);
        this.expectedFingerprint = normalizeFingerprint(fingerprint);
        this.trustOnFirstUse = trustOnFirstUse;
        if (this.expectedFingerprint.isEmpty() && !trustOnFirstUse) {
            throw new IllegalArgumentException("HQ certificate fingerprint is required");
        }
    }

    static PinnedHqClient firstUseProbe(String baseUrl) {
        return new PinnedHqClient(baseUrl, "", true);
    }

    Response get(String route, JSONObject credentials, String enrollmentSecret) throws Exception {
        return request("GET", route, null, credentials, enrollmentSecret);
    }

    Response post(String route, JSONObject body, JSONObject credentials) throws Exception {
        return request("POST", route, body, credentials, null);
    }

    private Response request(
            String method,
            String route,
            JSONObject body,
            JSONObject credentials,
            String enrollmentSecret
    ) throws Exception {
        URL url = new URL(baseUrl + route);
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IllegalArgumentException("SentryLoom HQ must use HTTPS");
        }

        final X509Certificate[] peer = new X509Certificate[1];
        X509TrustManager pinnedTrust = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
                throw new java.security.cert.CertificateException("Client-certificate trust is not supported");
            }
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
                if (chain == null || chain.length == 0) {
                    throw new java.security.cert.CertificateException("HQ did not present a certificate");
                }
                String presented;
                try {
                    presented = sha256(chain[0].getEncoded());
                } catch (Exception error) {
                    throw new java.security.cert.CertificateException(error);
                }
                if (!presented.equals(expectedFingerprint) &&
                        !(trustOnFirstUse && expectedFingerprint.isEmpty())) {
                    throw new java.security.cert.CertificateException(
                            "HQ certificate fingerprint mismatch"
                    );
                }
                peer[0] = chain[0];
            }
        };
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, new TrustManager[]{pinnedTrust}, new SecureRandom());

        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(ssl.getSocketFactory());
        HostnameVerifier pinnedIdentity = (hostname, session) -> true;
        connection.setHostnameVerifier(pinnedIdentity);
        connection.setRequestMethod(method);
        connection.setConnectTimeout(15_000);
        connection.setReadTimeout(30_000);
        connection.setRequestProperty("Accept", "application/json");
        if (credentials != null) {
            connection.setRequestProperty(
                    "Authorization", "Bearer " + credentials.getString("token")
            );
            connection.setRequestProperty(
                    "X-SentryLoom-Device", credentials.getString("deviceId")
            );
        } else if (enrollmentSecret != null) {
            connection.setRequestProperty("Authorization", "Enrollment " + enrollmentSecret);
        }
        if (body != null) {
            byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setDoOutput(true);
            connection.setFixedLengthStreamingMode(bytes.length);
            connection.setRequestProperty("Content-Type", "application/json");
            try (OutputStream output = connection.getOutputStream()) {
                output.write(bytes);
            }
        }
        int status = connection.getResponseCode();
        InputStream stream = status >= 200 && status < 300
                ? connection.getInputStream() : connection.getErrorStream();
        StringBuilder text = new StringBuilder();
        if (stream != null) {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8)
            )) {
                char[] buffer = new char[4096];
                int count;
                while ((count = reader.read(buffer)) >= 0) {
                    if (text.length() + count > 2 * 1024 * 1024) {
                        throw new IllegalStateException("HQ response is too large");
                    }
                    text.append(buffer, 0, count);
                }
            }
        }
        JSONObject result = text.length() == 0 ? new JSONObject() : new JSONObject(text.toString());
        if (status < 200 || status >= 300) {
            throw new IllegalStateException(result.optString("error", "HQ request failed (" + status + ")"));
        }
        if (peer[0] == null) throw new IllegalStateException("HQ certificate verification failed");
        return new Response(result, sha256(peer[0].getEncoded()));
    }

    static String normalizeFingerprint(String value) {
        if (value == null) return "";
        String clean = value.replaceAll("[^A-Fa-f0-9]", "").toUpperCase(Locale.ROOT);
        if (!clean.isEmpty() && clean.length() != 64) {
            throw new IllegalArgumentException("Enter a SHA-256 certificate fingerprint");
        }
        return clean;
    }

    private static String normalizeUrl(String value) {
        String clean = value == null ? "" : value.trim();
        while (clean.endsWith("/")) clean = clean.substring(0, clean.length() - 1);
        if (!clean.startsWith("https://")) {
            throw new IllegalArgumentException("SentryLoom HQ must use HTTPS");
        }
        return clean;
    }

    static String sha256(byte[] value) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder result = new StringBuilder(64);
        for (byte item : hash) result.append(String.format(Locale.ROOT, "%02X", item));
        return result.toString();
    }

    static String base64Url(byte[] value) {
        return Base64.encodeToString(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }
}
