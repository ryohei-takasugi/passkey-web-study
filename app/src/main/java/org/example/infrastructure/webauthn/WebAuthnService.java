package org.example.infrastructure.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.example.domain.model.CredentialRecord;
import org.example.domain.repository.CredentialRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * WebAuthn プロトコルの登録・認証オプション生成と検証を担当するサービス。
 * webauthn4j-core を直接使用する。
 */
public class WebAuthnService {

    /** セッションに保存するフロー種別のキー。 */
    public static final String SESSION_FLOW_KEY = "webauthn.flow";

    /** 登録フローを示す定数。 */
    public static final String FLOW_REGISTER = "register";

    /** 認証フローを示す定数。 */
    public static final String FLOW_LOGIN = "login";

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnService.class);
    private static final Base64.Encoder B64_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();

    private final Vertx vertx;
    private final CredentialRepository credentialRepository;
    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    private final String rpId;
    private final String rpName;
    private final Origin origin;

    /**
     * @param vertx                Vert.x インスタンス
     * @param credentialRepository クレデンシャルリポジトリ
     * @param rpId                 Relying Party ID
     * @param rpName               Relying Party 名
     * @param originUrl            WebAuthn オリジン URL
     */
    public WebAuthnService(Vertx vertx, CredentialRepository credentialRepository,
                           String rpId, String rpName, String originUrl) {
        this.vertx                = vertx;
        this.credentialRepository = credentialRepository;
        this.rpId                 = rpId;
        this.rpName               = rpName;
        this.origin               = new Origin(originUrl);
        this.objectConverter      = new ObjectConverter();
        this.webAuthnManager      = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    /**
     * 登録オプション（PublicKeyCredentialCreationOptions）を生成する。
     *
     * @param userId ユーザーID
     * @return challenge フィールドを含む WebAuthn 登録オプション JSON
     */
    public JsonObject createRegistrationOptions(String userId) {
        String challenge     = generateChallenge();
        String userIdEncoded = B64_ENC.encodeToString(userId.getBytes());

        JsonObject options = new JsonObject()
            .put("rp", new JsonObject().put("id", rpId).put("name", rpName))
            .put("user", new JsonObject()
                .put("id", userIdEncoded)
                .put("name", userId)
                .put("displayName", userId))
            .put("challenge", challenge)
            .put("pubKeyCredParams", new JsonArray()
                .add(new JsonObject().put("type", "public-key").put("alg", -7))
                .add(new JsonObject().put("type", "public-key").put("alg", -257)))
            .put("timeout", 60000)
            .put("attestation", "none")
            .put("authenticatorSelection", new JsonObject()
                .put("userVerification", "required")
                .put("requireResidentKey", false));

        return options;
    }
    /**
     * 認証オプション（PublicKeyCredentialRequestOptions）を生成する。
     *
     * @param userId ユーザーID
     * @return challenge・allowCredentials フィールドを含む WebAuthn 認証オプション JSON
     */
    public Future<JsonObject> createAuthenticationOptions(String userId) {
        Future<List<CredentialRecord>> findFuture = credentialRepository.find(userId, null);
        return findFuture.compose(records -> {
            return buildAuthOptions(userId, records);
        });
    }

    /**
     * 登録コールバックを検証し、クレデンシャルを保存する。
     *
     * @param challenge base64url エンコード済みチャレンジ
     * @param userId    ユーザーID
     * @param body      ブラウザからの WebAuthn レスポンス JSON
     * @return 保存した CredentialRecord
     */
    public Future<CredentialRecord> verifyRegistration(String challenge, String userId,
                                                        JsonObject body) {
        Future<CredentialRecord> blockingFuture = vertx.executeBlocking(() -> {
            return doVerifyRegistration(challenge, userId, body);
        });
        return blockingFuture.compose(record -> {
            Future<Void> storeFuture = credentialRepository.store(record);
            return storeFuture.map(v -> {
                return record;
            });
        });
    }

    /**
     * 認証コールバックを検証し、署名カウンターを更新する。
     *
     * @param challenge base64url エンコード済みチャレンジ
     * @param userId    ユーザーID
     * @param body      ブラウザからの WebAuthn レスポンス JSON
     * @return 更新後の CredentialRecord
     */
    public Future<CredentialRecord> verifyAuthentication(String challenge, String userId,
                                                          JsonObject body) {
        String credentialId = body.getString("id");
        Future<List<CredentialRecord>> findFuture = credentialRepository.find(userId, credentialId);
        return findFuture.compose(records -> {
            return verifyAuthWithRecord(challenge, body, records);
        });
    }

    // ── プライベートヘルパー ────────────────────────────────────────

    private String generateChallenge() {
        return B64_ENC.encodeToString(new DefaultChallenge().getValue());
    }

    private Future<JsonObject> buildAuthOptions(String userId, List<CredentialRecord> records) {
        if (records.isEmpty()) {
            return Future.failedFuture("no credentials found for userId: " + userId);
        }
        String challenge = generateChallenge();

        JsonArray allowCredentials = new JsonArray();
        for (CredentialRecord r : records) {
            allowCredentials.add(new JsonObject()
                .put("type", "public-key")
                .put("id", r.credentialId()));
        }

        JsonObject options = new JsonObject()
            .put("challenge", challenge)
            .put("allowCredentials", allowCredentials)
            .put("rpId", rpId)
            .put("timeout", 60000)
            .put("userVerification", "required");

        return Future.succeededFuture(options);
    }

    private CredentialRecord doVerifyRegistration(String challenge, String userId,
                                                   JsonObject body) {
        JsonObject response      = body.getJsonObject("response");
        byte[] clientDataJSON    = B64_DEC.decode(response.getString("clientDataJSON"));
        byte[] attestationObject = B64_DEC.decode(response.getString("attestationObject"));

        RegistrationRequest request = new RegistrationRequest(attestationObject, clientDataJSON);
        ServerProperty serverProp = new ServerProperty(
            origin, rpId, new DefaultChallenge(B64_DEC.decode(challenge))
        );
        List<PublicKeyCredentialParameters> pubKeyParams = List.of(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                                              COSEAlgorithmIdentifier.ES256),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                                              COSEAlgorithmIdentifier.RS256)
        );
        RegistrationParameters params = new RegistrationParameters(serverProp, pubKeyParams,
                                                                    true, true);

        RegistrationData data = webAuthnManager.verify(request, params);

        AttestedCredentialData credData = data.getAttestationObject()
            .getAuthenticatorData()
            .getAttestedCredentialData();

        byte[] credentialIdBytes = credData.getCredentialId();
        byte[] coseKeyBytes      = objectConverter.getCborConverter()
            .writeValueAsBytes(credData.getCOSEKey());
        long   signCount         = data.getAttestationObject()
            .getAuthenticatorData()
            .getSignCount();
        String aaguid            = credData.getAaguid().getValue().toString();

        logger.info("registration verified: userId={} credentialId={}",
            userId, B64_ENC.encodeToString(credentialIdBytes));

        return new CredentialRecord(
            B64_ENC.encodeToString(credentialIdBytes),
            userId,
            B64_ENC.encodeToString(coseKeyBytes),
            signCount,
            aaguid
        );
    }

    private Future<CredentialRecord> verifyAuthWithRecord(String challenge, JsonObject body,
                                                           List<CredentialRecord> records) {
        if (records.isEmpty()) {
            return Future.failedFuture("credential not found");
        }
        CredentialRecord stored = records.get(0);

        Future<CredentialRecord> blockingFuture = vertx.executeBlocking(() -> {
            return doVerifyAuthentication(challenge, body, stored);
        });
        return blockingFuture.compose(updated -> {
            Future<Void> updateFuture = credentialRepository.updateCounter(
                    updated.credentialId(), updated.signCount());
            return updateFuture.map(v -> {
                return updated;
            });
        });
    }

    @SuppressWarnings("deprecation")
    private CredentialRecord doVerifyAuthentication(String challenge, JsonObject body,
                                                     CredentialRecord stored) {
        JsonObject response        = body.getJsonObject("response");
        byte[] clientDataJSON      = B64_DEC.decode(response.getString("clientDataJSON"));
        byte[] authenticatorData   = B64_DEC.decode(response.getString("authenticatorData"));
        byte[] signature           = B64_DEC.decode(response.getString("signature"));
        String userHandleStr       = response.getString("userHandle");
        byte[] userHandle          = userHandleStr != null ? B64_DEC.decode(userHandleStr) : null;
        byte[] credentialIdBytes   = B64_DEC.decode(body.getString("rawId"));

        COSEKey coseKey = objectConverter.getCborConverter()
            .readValue(B64_DEC.decode(stored.publicKeyCose()), COSEKey.class);

        AttestedCredentialData attestedCredData = new AttestedCredentialData(
            new AAGUID(UUID.fromString(stored.aaguid())),
            credentialIdBytes,
            coseKey
        );
        AuthenticatorImpl authenticator = new AuthenticatorImpl(
            attestedCredData, null, stored.signCount()
        );

        AuthenticationRequest authRequest = new AuthenticationRequest(
            credentialIdBytes, userHandle, authenticatorData, clientDataJSON, signature
        );
        ServerProperty serverProp = new ServerProperty(
            origin, rpId, new DefaultChallenge(B64_DEC.decode(challenge))
        );
        AuthenticationParameters authParams = new AuthenticationParameters(
            serverProp, authenticator, true, true
        );

        AuthenticationData authData = webAuthnManager.verify(authRequest, authParams);
        long newCount = authData.getAuthenticatorData().getSignCount();

        logger.info("authentication verified: userId={} credentialId={} newCount={}",
            stored.userId(), stored.credentialId(), newCount);

        return new CredentialRecord(
            stored.credentialId(), stored.userId(),
            stored.publicKeyCose(), newCount, stored.aaguid()
        );
    }
}
