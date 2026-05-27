package org.example.infrastructure.webauthn;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.credential.CredentialRecordImpl;
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
 * WebAuthn / Passkey プロトコルの登録・認証を担当するサービスクラス。
 *
 * <h2>WebAuthn とは</h2>
 * WebAuthn（Web Authentication）は W3C が標準化した、パスワードを使わない認証の仕組みです。
 * ブラウザと認証器（スマートフォンの顔認証・指紋センサー、セキュリティキーなど）が連携して
 * 公開鍵暗号を使った認証を行います。
 *
 * <ul>
 *   <li><b>秘密鍵</b>はデバイスの安全な領域（セキュアエンクレーブ）に保存され、<b>外に出ない</b></li>
 *   <li><b>公開鍵</b>だけをサーバーが保持する。漏洩しても悪用できない</li>
 *   <li>「Passkey」は WebAuthn クレデンシャルをクラウド同期できるようにした形態
 *       （例: iCloud Keychain, Google Password Manager）</li>
 * </ul>
 *
 * <h2>2 つのフロー概要</h2>
 *
 * <h3>① 登録フロー（Registration）</h3>
 * <pre>
 *   Browser                  Server (このクラス)         Authenticator（デバイス）
 *     |                           |                           |
 *     | POST /webauthn/register   |                           |
 *     |-------------------------->|                           |
 *     |   challenge 等を返す      |                           |
 *     |<--------------------------|                           |
 *     |                           |                           |
 *     | navigator.credentials     |                           |
 *     |   .create(options) ------>|                           |
 *     |             生体認証 ・PIN|<--------------------------|
 *     |             鍵ペア生成    |                           |
 *     | attestationObject 等      |                           |
 *     |<- - - - - - - - - - - -  |                           |
 *     |                           |                           |
 *     | POST /webauthn/callback   |                           |
 *     |-------------------------->|                           |
 *     |   検証 OK → 公開鍵を保存  |                           |
 *     |<--------------------------|                           |
 * </pre>
 *
 * <h3>② 認証フロー（Authentication）</h3>
 * <pre>
 *   Browser                  Server (このクラス)         Authenticator（デバイス）
 *     |                           |                           |
 *     | POST /webauthn/login      |                           |
 *     |-------------------------->|                           |
 *     |   challenge 等を返す      |                           |
 *     |<--------------------------|                           |
 *     |                           |                           |
 *     | navigator.credentials     |                           |
 *     |   .get(options) --------->|                           |
 *     |             生体認証・PIN |<--------------------------|
 *     |             署名を作成    |                           |
 *     | signature 等              |                           |
 *     |<- - - - - - - - - - - -  |                           |
 *     |                           |                           |
 *     | POST /webauthn/callback   |                           |
 *     |-------------------------->|                           |
 *     |   署名検証 OK → ログイン  |                           |
 *     |<--------------------------|                           |
 * </pre>
 *
 * <h2>このクラスの責務</h2>
 * <ul>
 *   <li>登録・認証のオプション JSON 生成（ブラウザの {@code navigator.credentials} API に渡す値）</li>
 *   <li>ブラウザからのコールバックデータを webauthn4j で検証</li>
 *   <li>検証済みクレデンシャルを {@link CredentialRepository} 経由で永続化</li>
 * </ul>
 *
 * <h2>参照すべき公式ドキュメント</h2>
 * <ul>
 *   <li>W3C WebAuthn Level 3 仕様（一次情報）:
 *       <a href="https://www.w3.org/TR/webauthn-3/">https://www.w3.org/TR/webauthn-3/</a></li>
 *   <li>MDN Web Authentication API（実装者向け解説）:
 *       <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API">MDN</a></li>
 *   <li>webauthn4j 公式ドキュメント（このライブラリの使い方）:
 *       <a href="https://webauthn4j.github.io/webauthn4j/en/">webauthn4j</a></li>
 *   <li>FIDO Alliance 仕様一覧（Passkey の上位概念）:
 *       <a href="https://fidoalliance.org/specifications/">FIDO Alliance</a></li>
 * </ul>
 */
public class WebAuthnService {

    // ──────────────────────────────────────────────────────────────────────────
    // セッション連携用定数
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * セッションに保存するフロー種別のキー。
     * 登録・認証のどちらのコールバックかを判定するために {@link PasskeyCallbackHandler} が参照する。
     * 値は {@link #FLOW_REGISTER} または {@link #FLOW_LOGIN}。
     */
    public static final String SESSION_FLOW_KEY = "webauthn.flow";

    /**
     * 登録フローを示す定数。
     * セッションの {@link #SESSION_FLOW_KEY} にこの値が入っている場合、
     * {@code /webauthn/callback} は登録検証として処理する。
     */
    public static final String FLOW_REGISTER = "register";

    /**
     * 認証フローを示す定数。
     * セッションの {@link #SESSION_FLOW_KEY} にこの値が入っている場合、
     * {@code /webauthn/callback} は認証検証として処理する。
     */
    public static final String FLOW_LOGIN = "login";

    // ──────────────────────────────────────────────────────────────────────────
    // 内部フィールド
    // ──────────────────────────────────────────────────────────────────────────

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnService.class);

    /**
     * Base64url エンコーダー（パディングなし）。
     * WebAuthn では全バイナリデータを base64url エンコードして JSON に乗せる。
     * パディング文字 '=' は含めないのが仕様（RFC 4648 §5 の "unpadded" 形式）。
     */
    private static final Base64.Encoder B64_ENC = Base64.getUrlEncoder().withoutPadding();

    /** Base64url デコーダー。ブラウザから受け取った文字列をバイト列に戻すために使用。 */
    private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();

    /** Vert.x インスタンス。暗号演算をイベントループ外で実行するための {@code executeBlocking} に使用。 */
    private final Vertx vertx;

    /** クレデンシャル永続化。登録時に公開鍵を保存し、認証時に取り出す。 */
    private final CredentialRepository credentialRepository;

    /**
     * webauthn4j のメインクラス。登録・認証双方の検証ロジックを提供する。
     *
     * <p>{@code createNonStrictWebAuthnManager()} を使っている理由：
     * "Strict" モードでは attestation ステートメントの証明書チェーン検証や
     * FIDO Metadata Service (MDS) との照合を行う。
     * 開発・学習目的では証明書が自己署名であることが多く、その検証を
     * スキップする "NonStrict" モードが適切。</p>
     *
     * <p><b>本番での検討</b>: 高いセキュリティが必要な場面では {@code createNonStrictWebAuthnManager()}
     * ではなく、{@code WebAuthnManager} を直接コンストラクタで構築し
     * {@link com.webauthn4j.anchor.TrustAnchorRepository} に MDS を接続することで
     * デバイスの信頼性検証（attestation verification）が可能になる。<br>
     * 参照: <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation">W3C §8 Attestation</a></p>
     */
    private final WebAuthnManager webAuthnManager;

    /**
     * CBOR（Concise Binary Object Representation）と Java オブジェクト間の変換器。
     *
     * <p>WebAuthn では公開鍵を COSE（CBOR Object Signing and Encryption）形式でエンコードする。
     * COSE は CBOR をベースにした鍵・署名フォーマットで、JSON より小さい。</p>
     *
     * <ul>
     *   <li>登録時: {@code getCborMapper().writeValueAsBytes(coseKey)} で公開鍵を DB 保存用バイト列に変換</li>
     *   <li>認証時: {@code getCborMapper().readValue(bytes, COSEKey.class)} で DB からロードした公開鍵を復元</li>
     * </ul>
     *
     * <p>参照:
     * <a href="https://www.rfc-editor.org/rfc/rfc8152">RFC 8152 (COSE)</a>,
     * <a href="https://www.iana.org/assignments/cose/cose.xhtml">IANA COSE アルゴリズム登録簿</a></p>
     */
    private final ObjectConverter objectConverter;

    /**
     * Relying Party ID（RP ID）。
     *
     * <p>WebAuthn でクレデンシャルの「所有権」を表すドメイン文字列（例: {@code "example.com"}）。
     * ブラウザは RP ID のハッシュ（SHA-256）を認証器データに含めて署名するため、
     * <b>フィッシングサイトが正規サイトになりすますことを防止</b>できる。</p>
     *
     * <ul>
     *   <li>登録時: ブラウザに RP ID を伝え、認証器データに埋め込ませる</li>
     *   <li>検証時: サーバーが計算した rpIdHash と authenticatorData 内の rpIdHash を照合</li>
     *   <li>RP ID は有効な登録済みドメインのサフィックスでなければならない
     *       （例: {@code "login.example.com"} のページでは {@code "example.com"} も使用可能）</li>
     * </ul>
     *
     * <p>参照: <a href="https://www.w3.org/TR/webauthn-3/#rp-id">W3C §4 RP ID</a></p>
     */
    private final String rpId;

    /**
     * Relying Party 名。登録時にブラウザ／認証器の UI に表示されるサービス名（例: "My App"）。
     * セキュリティ検証には使われないが、UX に影響する。
     */
    private final String rpName;

    /**
     * 想定オリジン。ブラウザが clientDataJSON に埋め込む {@code origin} と照合するために使用。
     *
     * <p>例: {@code new Origin("https://example.com")}
     * オリジンはスキーム・ホスト・ポートで構成される（例: {@code https://localhost:8080}）。
     * <b>origin が一致しないリクエストは検証で必ず弾かれる</b>ため、
     * CSRF・フィッシング対策として重要な役割を担う。</p>
     *
     * <p>参照: <a href="https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin">W3C §5.8.1 origin</a></p>
     */
    private final Origin origin;

    // ──────────────────────────────────────────────────────────────────────────
    // コンストラクタ
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * WebAuthnService を構築する。
     *
     * @param vertx                Vert.x インスタンス（executeBlocking 用）
     * @param credentialRepository クレデンシャル永続化リポジトリ
     * @param rpId                 Relying Party ID（通常はドメイン名、例: {@code "localhost"}）
     * @param rpName               Relying Party 名（認証器 UI に表示される名前、例: {@code "Passkey Demo"}）
     * @param originUrl            想定オリジン URL（例: {@code "https://localhost:8080"}）
     */
    public WebAuthnService(Vertx vertx, CredentialRepository credentialRepository,
                           String rpId, String rpName, String originUrl) {
        this.vertx                = vertx;
        this.credentialRepository = credentialRepository;
        this.rpId                 = rpId;
        this.rpName               = rpName;
        this.origin               = new Origin(originUrl);
        this.objectConverter      = new ObjectConverter();
        // NonStrict: 開発・学習用。attestation ステートメントの証明書検証をスキップする。
        // 本番で高いセキュリティが必要な場合は WebAuthnManager のフルコンストラクタを使い
        // MDS（FIDO Metadata Service）と接続する。
        this.webAuthnManager      = WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // 公開メソッド — 登録
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * 登録オプション（{@code PublicKeyCredentialCreationOptions}）を生成して返す。
     *
     * <p>このメソッドが返す JSON はブラウザ側の {@code navigator.credentials.create(options)}
     * に渡す。ブラウザは認証器（TouchID・FaceID・セキュリティキーなど）を起動し、
     * 鍵ペアを生成させる。</p>
     *
     * <p>参照: <a href="https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions">
     * W3C §5.4 PublicKeyCredentialCreationOptions</a></p>
     *
     * <h3>返す JSON の各フィールド解説</h3>
     * <pre>
     * {
     *   "rp": { "id": "localhost", "name": "Passkey Demo" },
     *   "user": { "id": "dXNlci1hbGljZQ", "name": "user-alice", "displayName": "user-alice" },
     *   "challenge": "ランダム16バイト以上のbase64url文字列",
     *   "pubKeyCredParams": [ { "type": "public-key", "alg": -7 }, ... ],
     *   "timeout": 60000,
     *   "attestation": "none",
     *   "authenticatorSelection": { "userVerification": "required", "requireResidentKey": false }
     * }
     * </pre>
     *
     * @param userId ユーザーID（人間が読める識別子。{@code user.name} と {@code user.displayName} に使用）
     * @return {@code challenge} フィールドを含む WebAuthn 登録オプション JSON。
     *         このチャレンジは後続の {@link #verifyRegistration} 呼び出し時に照合する。
     */
    public JsonObject createRegistrationOptions(String userId) {
        // ── チャレンジ生成 ──────────────────────────────────────────────────
        // チャレンジはリプレイ攻撃防止用のワンタイムノンス。
        // 毎回ランダムに生成し、ブラウザに送る。ブラウザ（認証器）はこの値を署名の材料に含める。
        // サーバーは後でチャレンジを照合することで「今回の登録リクエストのために署名された」ことを確認。
        String challenge     = generateChallenge();

        // ── ユーザー識別子 ──────────────────────────────────────────────────
        // user.id は「user handle」と呼ばれるバイト列（base64url エンコード済み）。
        // 認証器がクレデンシャルと紐付けて保存するため、一意かつ不変である必要がある。
        // 注意: displayName や email など個人情報を直接入れるべきではない（プライバシー考慮）。
        // 参照: https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id
        String userIdEncoded = B64_ENC.encodeToString(userId.getBytes());

        JsonObject options = new JsonObject()
            // ── rp（Relying Party）──────────────────────────────────────────
            // id: RP ID（フィッシング防止の要。このドメインと一致する origin からしか使えない鍵になる）
            // name: 認証器の UI に表示されるサービス名
            .put("rp", new JsonObject().put("id", rpId).put("name", rpName))

            // ── user ──────────────────────────────────────────────────────────
            // id: user handle（base64url）。認証器がクレデンシャルに紐付けて保存する
            // name: アカウント名（UI 表示用、ユニーク推奨）
            // displayName: 表示名（UI 表示用、より人間が読みやすい名前）
            .put("user", new JsonObject()
                .put("id", userIdEncoded)
                .put("name", userId)
                .put("displayName", userId))

            // ── challenge ────────────────────────────────────────────────────
            // リプレイ攻撃防止用ノンス。base64url 形式で送り、検証時に照合する。
            // 最低 16 バイト以上必要（W3C 勧告）
            .put("challenge", challenge)

            // ── pubKeyCredParams ──────────────────────────────────────────────
            // サーバーが受け入れる公開鍵アルゴリズムのリスト。認証器は上から試す。
            //   alg: -7  → ES256（ECDSA with SHA-256, NIST P-256 曲線）: 現行主流
            //   alg: -257 → RS256（RSASSA-PKCS1-v1_5 with SHA-256）: 古いデバイス向け
            // alg 番号は IANA COSE Algorithm Registry で定義:
            //   https://www.iana.org/assignments/cose/cose.xhtml
            .put("pubKeyCredParams", new JsonArray()
                .add(new JsonObject().put("type", "public-key").put("alg", -7))
                .add(new JsonObject().put("type", "public-key").put("alg", -257)))

            // ── timeout ──────────────────────────────────────────────────────
            // ブラウザが認証器の応答を待つ最大時間（ミリ秒）。60 秒は一般的な値。
            // ユーザーが生体認証を完了するまでの猶予時間。
            .put("timeout", 60000)

            // ── attestation ──────────────────────────────────────────────────
            // "none": 認証器のデバイス証明書（attestation statement）を要求しない。
            // 一般の Web サービスでは "none" が推奨。証明書検証が不要で UX が高い。
            // "direct" や "indirect" を指定するとデバイスの製造元証明書を取得できるが、
            // 検証には FIDO Metadata Service (MDS) との連携が必要になる。
            // 参照: https://www.w3.org/TR/webauthn-3/#sctn-attestation
            // 【今後の検討】 高保証環境（金融・政府）では "direct" + MDS 照合で
            //               デバイスの信頼性を確認することを検討する
            .put("attestation", "none")

            // ── authenticatorSelection ────────────────────────────────────────
            .put("authenticatorSelection", new JsonObject()
                // userVerification: "required" → 生体認証・PIN 入力を必須にする。
                // "preferred" にするとデバイスが対応していれば生体認証を試みるが、
                // 対応していない場合はスキップされる。Passkey の場合は "required" が推奨。
                // 参照: https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification
                .put("userVerification", "required")

                // requireResidentKey: false → discoverable credential（常駐鍵）を強制しない。
                // true にすると認証器の内部ストレージに鍵が保存され、
                // 認証時に allowCredentials を空にしても使えるようになる（パスワードレス）。
                // スマートフォンの Passkey は常駐鍵として扱われることが多い。
                // 参照: https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-requireresidentkey
                // 【今後の検討】 "residentKey": "preferred" に変更すると Passkey UX が向上する
                .put("requireResidentKey", false));

        // 【今後の検討】 excludeCredentials を追加することで、
        //               既に登録済みのクレデンシャルを再登録しようとするのを防げる。
        //               credentialRepository.find(userId, null) で取得した ID リストを設定する。
        // 例:
        //   "excludeCredentials": [{"type": "public-key", "id": "<credentialId>"}]

        return options;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // 公開メソッド — 認証
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * 認証オプション（{@code PublicKeyCredentialRequestOptions}）を生成して返す。
     *
     * <p>このメソッドが返す JSON はブラウザ側の {@code navigator.credentials.get(options)}
     * に渡す。ブラウザは {@code allowCredentials} に列挙されたクレデンシャルから
     * 使用可能なものを選び、認証器（TouchID・FaceID・セキュリティキーなど）で署名する。</p>
     *
     * <p>DB からクレデンシャルを取得する必要があるため、このメソッドは {@link Future} を返す。</p>
     *
     * <p>参照: <a href="https://www.w3.org/TR/webauthn-3/#dictionary-assertion-options">
     * W3C §5.5 PublicKeyCredentialRequestOptions</a></p>
     *
     * @param userId 認証しようとしているユーザーの ID
     * @return {@code challenge} と {@code allowCredentials} を含む WebAuthn 認証オプション JSON
     */
    public Future<JsonObject> createAuthenticationOptions(String userId) {
        // userId に紐付くすべてのクレデンシャルを取得する。
        // allowCredentials にクレデンシャル ID を列挙することで、
        // ブラウザはその中から使える鍵を探す（複数デバイスで登録している場合にも対応）。
        Future<List<CredentialRecord>> findFuture = credentialRepository.find(userId, null);
        return findFuture.compose(records -> {
            return buildAuthOptions(userId, records);
        });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // 公開メソッド — コールバック検証
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * 登録コールバックを検証し、クレデンシャルを永続化する。
     *
     * <p>ブラウザが {@code navigator.credentials.create()} を完了した後、
     * {@code /webauthn/callback} に POST してくる JSON を受け取り、
     * webauthn4j で検証した後 {@link CredentialRepository} に公開鍵を保存する。</p>
     *
     * <p><b>なぜ {@code executeBlocking} を使うか:</b><br>
     * {@code webAuthnManager.verify()} は ECDSA 署名検証など CPU バウンドな暗号演算を行う。
     * Vert.x のイベントループスレッドでブロッキング処理を行うとスループットが低下するため、
     * ワーカースレッドプールに委譲する。</p>
     *
     * @param challenge セッションに保存しておいたチャレンジ（base64url エンコード済み）
     * @param userId    登録対象のユーザー ID
     * @param body      ブラウザからの WebAuthn レスポンス JSON
     *                  （{@code id}, {@code rawId}, {@code response.clientDataJSON},
     *                  {@code response.attestationObject} などを含む）
     * @return 永続化済みの {@link CredentialRecord}（公開鍵・signCount 等を含む）
     */
    public Future<CredentialRecord> verifyRegistration(String challenge, String userId,
                                                        JsonObject body) {
        // ① 検証はワーカースレッドで実行（暗号演算のため）
        Future<CredentialRecord> blockingFuture = vertx.executeBlocking(() -> {
            return doVerifyRegistration(challenge, userId, body);
        });
        // ② 検証成功後、公開鍵を DB に保存する
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
     * <p>ブラウザが {@code navigator.credentials.get()} を完了した後、
     * {@code /webauthn/callback} に POST してくる JSON を受け取り、
     * DB から公開鍵をロードして署名を検証する。</p>
     *
     * <p><b>署名カウンターについて:</b><br>
     * WebAuthn 認証器は認証のたびにカウンターをインクリメントし、
     * {@code authenticatorData} に含める。サーバーは前回より大きい値かを確認する。
     * カウンターが前回以下の場合、認証器がクローンされた可能性がある（リプレイ攻撃）。
     * webauthn4j はこのチェックを内部で自動的に行う。<br>
     * 参照: <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">
     * W3C §13.1 Sign Count</a></p>
     *
     * @param challenge セッションに保存しておいたチャレンジ（base64url エンコード済み）
     * @param userId    認証しようとしているユーザーの ID
     * @param body      ブラウザからの WebAuthn レスポンス JSON
     *                  （{@code id}, {@code rawId}, {@code response.clientDataJSON},
     *                  {@code response.authenticatorData}, {@code response.signature} 等を含む）
     * @return signCount が更新された {@link CredentialRecord}
     */
    public Future<CredentialRecord> verifyAuthentication(String challenge, String userId,
                                                          JsonObject body) {
        // ブラウザが使用したクレデンシャルの ID を取り出す。
        // 1 ユーザーが複数デバイスで登録している場合、どの公開鍵で検証するかを特定するために必要。
        String credentialId = body.getString("id");
        Future<List<CredentialRecord>> findFuture = credentialRepository.find(userId, credentialId);
        return findFuture.compose(records -> {
            return verifyAuthWithRecord(challenge, body, records);
        });
    }

    // ──────────────────────────────────────────────────────────────────────────
    // プライベートヘルパー
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * ランダムなチャレンジを生成して base64url 文字列で返す。
     *
     * <p>webauthn4j の {@link DefaultChallenge} は内部で {@code SecureRandom} を使い
     * 16 バイト以上のランダムバイト列を生成する（W3C 要件: 最低 16 バイト）。</p>
     */
    private String generateChallenge() {
        // DefaultChallenge() がセキュアランダムでバイト列を生成する。
        // getValue() でバイト列を取り出し、base64url エンコードして文字列にする。
        return B64_ENC.encodeToString(new DefaultChallenge().getValue());
    }

    /**
     * 認証オプション JSON を構築する。
     *
     * @param userId  ユーザー ID（クレデンシャルが見つからない場合のエラーメッセージ用）
     * @param records DB から取得した、このユーザーのすべてのクレデンシャル
     * @return {@code PublicKeyCredentialRequestOptions} JSON
     */
    private Future<JsonObject> buildAuthOptions(String userId, List<CredentialRecord> records) {
        if (records.isEmpty()) {
            // クレデンシャルが 1 件もない = 未登録ユーザー
            return Future.failedFuture("no credentials found for userId: " + userId);
        }
        String challenge = generateChallenge();

        // allowCredentials: このユーザーが登録済みのクレデンシャル ID リスト。
        // ブラウザはこのリストを見て「自分のデバイスに対応する鍵があるか」を確認する。
        // 複数デバイスで登録している場合は複数エントリが入る。
        // 【今後の検討】 allowCredentials を空にすると "discoverable credential" フロー になり、
        //               userId の入力なしで認証できる（True パスワードレス体験）。
        //               ただし認証器側が常駐鍵に対応している必要がある。
        JsonArray allowCredentials = new JsonArray();
        for (CredentialRecord r : records) {
            allowCredentials.add(new JsonObject()
                .put("type", "public-key")
                .put("id", r.credentialId()));  // base64url エンコード済みの credentialId
        }

        JsonObject options = new JsonObject()
            // 登録時と同じく、リプレイ攻撃防止用のワンタイムノンス
            .put("challenge", challenge)
            // ブラウザが使用可能な鍵を絞り込むための ID リスト
            .put("allowCredentials", allowCredentials)
            // RP ID: 認証器データ内の rpIdHash と照合するドメイン
            .put("rpId", rpId)
            .put("timeout", 60000)
            // 登録時と同じく生体認証・PIN を必須にする
            .put("userVerification", "required");

        return Future.succeededFuture(options);
    }

    /**
     * 登録コールバックの実際の検証処理（ブロッキング）。
     *
     * <p>このメソッドは webauthn4j による暗号演算を含むため、
     * 呼び出し元 {@link #verifyRegistration} は必ず {@code executeBlocking} で包むこと。</p>
     *
     * <h3>検証ステップ（webauthn4j が内部で実行）</h3>
     * <ol>
     *   <li>clientDataJSON の JSON デコードと {@code type == "webauthn.create"} チェック</li>
     *   <li>clientDataJSON 内の {@code challenge} が送ったチャレンジと一致するか</li>
     *   <li>clientDataJSON 内の {@code origin} が設定した origin と一致するか</li>
     *   <li>attestationObject のデコード（CBOR）</li>
     *   <li>認証器データ内の {@code rpIdHash} が RP ID の SHA-256 と一致するか</li>
     *   <li>認証器データの UP（User Presence）フラグが立っているか</li>
     *   <li>UV（User Verification）フラグのチェック（{@code userVerificationRequired=true} の場合）</li>
     *   <li>pubKeyCredParams で指定したアルゴリズムで生成された鍵かどうか</li>
     * </ol>
     *
     * <p>参照: <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">
     * W3C §7.1 Registering a New Credential</a></p>
     *
     * @param challenge セッションに保存しておいたチャレンジ（base64url エンコード済み）
     * @param userId    登録対象のユーザー ID
     * @param body      ブラウザからの WebAuthn レスポンス JSON
     * @return ドメインモデルの {@link CredentialRecord}（永続化前の状態）
     */
    private CredentialRecord doVerifyRegistration(String challenge, String userId,
                                                   JsonObject body) {
        JsonObject response = body.getJsonObject("response");

        // ── ブラウザからのバイナリデータをデコード ───────────────────────────
        // clientDataJSON: ブラウザが生成した JSON 文字列をバイト列にしたもの。
        //   中身（デコードすると見られる）: { "type": "webauthn.create", "challenge": "...",
        //                                    "origin": "https://...", "crossOrigin": false }
        //   "type" で登録・認証を区別できる。"webauthn.create" が登録用。
        byte[] clientDataJSON    = B64_DEC.decode(response.getString("clientDataJSON"));

        // attestationObject: 認証器が生成した CBOR エンコードデータ。以下を含む:
        //   - fmt: attestation フォーマット（"none" など）
        //   - attStmt: attestation ステートメント（"none" では空）
        //   - authData: 認証器データ（rpIdHash・フラグ・signCount・AttestedCredentialData）
        //   参照: https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse
        byte[] attestationObject = B64_DEC.decode(response.getString("attestationObject"));

        // ── webauthn4j への入力オブジェクト組み立て ──────────────────────────

        // RegistrationRequest: clientDataJSON と attestationObject をまとめてライブラリに渡す入れ物
        RegistrationRequest request = new RegistrationRequest(attestationObject, clientDataJSON);

        // ServerProperty: サーバーが「期待する値」を定義する。ライブラリが検証に使用する。
        //   origin: クライアントが送ってきた origin と照合
        //   rpId: authenticatorData 内 rpIdHash と照合
        //   challenge: クライアントが署名したチャレンジと照合
        ServerProperty serverProp = ServerProperty.builder()
            .origin(origin)
            .rpId(rpId)
            .challenge(new DefaultChallenge(B64_DEC.decode(challenge)))
            .build();

        // pubKeyCredParams: サーバーが受け入れる公開鍵アルゴリズム。
        //   createRegistrationOptions で指定したものと一致させる必要がある。
        //   ES256 = ECDSA P-256（COSE alg -7）
        //   RS256 = RSASSA-PKCS1-v1_5 SHA-256（COSE alg -257）
        List<PublicKeyCredentialParameters> pubKeyParams = List.of(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                                              COSEAlgorithmIdentifier.ES256),
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                                              COSEAlgorithmIdentifier.RS256)
        );

        // RegistrationParameters: 検証のサーバーサイドパラメータ。
        //   第 3 引数 userVerificationRequired = true: UV フラグが必須。
        //             生体認証・PIN を行ったことを認証器データで確認する。
        //   第 4 引数 userPresenceRequired = true: UP フラグが必須。
        //             ユーザーが物理的にデバイスに触れたことを確認する（通常 true）。
        RegistrationParameters params = new RegistrationParameters(serverProp, pubKeyParams,
                                                                    true, true);

        // ── webauthn4j による検証実行 ────────────────────────────────────────
        // verify() は上記の検証ステップをすべて実行し、失敗すると例外をスローする。
        // 成功すると解析済みデータを含む RegistrationData を返す。
        RegistrationData data = webAuthnManager.verify(request, params);

        // ── 公開鍵情報の抽出 ─────────────────────────────────────────────────
        // AttestedCredentialData: 認証器データの中に埋め込まれている、
        //   今回生成されたクレデンシャルの情報（3 要素）:
        //     1. AAGUID: 認証器の種類を示す UUID（例: "adce0002-..." は Chrome Passkey のような値）
        //     2. credentialId: このクレデンシャルを一意に識別するバイト列
        //     3. COSEKey: 公開鍵（COSE フォーマット）
        AttestedCredentialData credData = data.getAttestationObject()
            .getAuthenticatorData()
            .getAttestedCredentialData();

        // credentialId: 今後の認証時に「どのクレデンシャルか」を識別するための一意 ID。
        //   ブラウザが allowCredentials にこの値を提示することで正しい鍵を選択できる。
        byte[] credentialIdBytes = credData.getCredentialId();

        // 公開鍵を CBOR シリアライズして保存する。
        // COSE フォーマットのまま保存する理由: 認証時に COSEKey オブジェクトに戻せるため。
        // objectConverter.getCborMapper() は非推奨でない Jackson 3 の CBORMapper を使用。
        byte[] coseKeyBytes      = objectConverter.getCborMapper()
            .writeValueAsBytes(credData.getCOSEKey());

        // signCount: 登録直後は 0。認証のたびにインクリメントされる。
        //   クローン検知（リプレイ攻撃防止）のために保存しておく。
        long   signCount         = data.getAttestationObject()
            .getAuthenticatorData()
            .getSignCount();

        // AAGUID: 認証器の「型番的 UUID」。
        //   例: "adce0002-35bc-c60a-648b-0b25f1f05503" は Google/Chrome の Passkey 実装を示す。
        //   FIDO Alliance の MDS（Metadata Service）でこの UUID を照合すると
        //   認証器の詳細情報（メーカー・認証レベル等）を取得できる。
        //   参照: https://fidoalliance.org/metadata/
        //   【今後の検討】 AAGUID を MDS と照合することで、信頼できる認証器のみ受け付けることが可能
        String aaguid            = credData.getAaguid().getValue().toString();

        logger.info("registration verified: userId={} credentialId={}",
            userId, B64_ENC.encodeToString(credentialIdBytes));

        // ドメインモデルに詰め替えて返す（永続化は呼び出し元が行う）
        return new CredentialRecord(
            B64_ENC.encodeToString(credentialIdBytes),  // credentialId（base64url）
            userId,
            B64_ENC.encodeToString(coseKeyBytes),       // 公開鍵（CBOR → base64url）
            signCount,
            aaguid
        );
    }

    /**
     * 認証コールバックの前処理。DB からクレデンシャルを取得してから検証を実行する。
     *
     * @param challenge セッションに保存しておいたチャレンジ（base64url エンコード済み）
     * @param body      ブラウザからの WebAuthn レスポンス JSON
     * @param records   DB から取得したクレデンシャルのリスト（通常 1 件）
     * @return signCount が更新された {@link CredentialRecord}
     */
    private Future<CredentialRecord> verifyAuthWithRecord(String challenge, JsonObject body,
                                                           List<CredentialRecord> records) {
        if (records.isEmpty()) {
            // credentialId に対応するクレデンシャルが DB に存在しない。
            // 未登録ユーザーや、他ユーザーの credentialId を送ってきた場合。
            return Future.failedFuture("credential not found");
        }
        // credentialId で絞り込んでいるため通常は 1 件。
        CredentialRecord stored = records.get(0);

        // 検証はワーカースレッドで実行（暗号演算のため）
        Future<CredentialRecord> blockingFuture = vertx.executeBlocking(() -> {
            return doVerifyAuthentication(challenge, body, stored);
        });
        // 検証成功後、更新された signCount を DB に書き戻す（クローン検知のため）
        return blockingFuture.compose(updated -> {
            Future<Void> updateFuture = credentialRepository.updateCounter(
                    updated.credentialId(), updated.signCount());
            return updateFuture.map(v -> {
                return updated;
            });
        });
    }

    /**
     * 認証コールバックの実際の検証処理（ブロッキング）。
     *
     * <p>このメソッドは webauthn4j による暗号演算を含むため、
     * 呼び出し元 {@link #verifyAuthWithRecord} は必ず {@code executeBlocking} で包むこと。</p>
     *
     * <h3>検証ステップ（webauthn4j が内部で実行）</h3>
     * <ol>
     *   <li>clientDataJSON の JSON デコードと {@code type == "webauthn.get"} チェック</li>
     *   <li>clientDataJSON 内の {@code challenge} が送ったチャレンジと一致するか</li>
     *   <li>clientDataJSON 内の {@code origin} が設定した origin と一致するか</li>
     *   <li>認証器データの {@code rpIdHash} が RP ID の SHA-256 と一致するか</li>
     *   <li>UP（User Presence）フラグのチェック</li>
     *   <li>UV（User Verification）フラグのチェック（{@code userVerificationRequired=true} の場合）</li>
     *   <li>ECDSA 署名検証: {@code signature} が (authenticatorData || SHA256(clientDataJSON))
     *       に対して DB の公開鍵で有効かどうか</li>
     *   <li>signCount が前回より大きいかのチェック（クローン検知）</li>
     * </ol>
     *
     * <p>参照: <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">
     * W3C §7.2 Verifying an Authentication Assertion</a></p>
     *
     * @param challenge セッションに保存しておいたチャレンジ（base64url エンコード済み）
     * @param body      ブラウザからの WebAuthn レスポンス JSON
     * @param stored    DB から取得した、このクレデンシャルの公開鍵等を含むレコード
     * @return signCount が更新された {@link CredentialRecord}
     */
    private CredentialRecord doVerifyAuthentication(String challenge, JsonObject body,
                                                     CredentialRecord stored) {
        JsonObject response = body.getJsonObject("response");

        // ── ブラウザからのバイナリデータをデコード ───────────────────────────

        // clientDataJSON: 登録時と同様。ただし "type": "webauthn.get"（認証用）になる。
        byte[] clientDataJSON      = B64_DEC.decode(response.getString("clientDataJSON"));

        // authenticatorData: 認証器が生成したバイナリデータ。以下を含む:
        //   - rpIdHash  (32 bytes): RP ID の SHA-256
        //   - flags     (1 byte) : UP（bit 0）・UV（bit 2）・BE（bit 3）・BS（bit 4）等
        //   - signCount (4 bytes): 単調増加カウンター（クローン検知に使用）
        //   ※ 認証時は AttestedCredentialData は含まれない（登録時のみ）
        //   参照: https://www.w3.org/TR/webauthn-3/#authenticator-data
        byte[] authenticatorData   = B64_DEC.decode(response.getString("authenticatorData"));

        // signature: 認証器が秘密鍵で生成した署名。
        //   署名対象 = authenticatorData || SHA-256(clientDataJSON)
        //   サーバーは DB に保存した公開鍵でこの署名を検証する。
        byte[] signature           = B64_DEC.decode(response.getString("signature"));

        // userHandle: 常駐鍵（discoverable credential）の場合、認証器が返すユーザー識別子。
        //   非常駐鍵では null になることがある。
        //   【今後の検討】 userHandle が存在する場合、stored.userId() と照合してより厳密な検証が可能
        String userHandleStr       = response.getString("userHandle");
        byte[] userHandle          = userHandleStr != null ? B64_DEC.decode(userHandleStr) : null;

        // rawId: クレデンシャル ID のバイナリ形式（body.id は base64url だが rawId はそのバイナリ）
        byte[] credentialIdBytes   = B64_DEC.decode(body.getString("rawId"));

        // ── DB から公開鍵を復元 ───────────────────────────────────────────────
        // 登録時に CBOR シリアライズして保存した公開鍵を、CBOR デシリアライズで復元する。
        // COSEKey は ECDSA（EC2COSEKey）または RSA（RSACOSEKey）の実装クラスになる。
        COSEKey coseKey = objectConverter.getCborMapper()
            .readValue(B64_DEC.decode(stored.publicKeyCose()), COSEKey.class);

        // ── webauthn4j 検証用オブジェクトの組み立て ──────────────────────────

        // AttestedCredentialData: DB に保存していた情報から再構築する。
        //   ライブラリが署名検証のために内部で公開鍵にアクセスする際に使用。
        //   認証時は attestation は不要なので AAGUID・credentialId・COSEKey の 3 要素のみ必要。
        AttestedCredentialData attestedCredData = new AttestedCredentialData(
            new AAGUID(UUID.fromString(stored.aaguid())),
            credentialIdBytes,
            coseKey
        );

        // CredentialRecordImpl: webauthn4j がクレデンシャルを表現するためのクラス。
        //   null 引数の意味（認証フローでは不要なフィールド）:
        //     - AttestationStatement: 認証フローでは不要（登録時のみ）
        //     - uvInitialized (Boolean): UV フラグが登録時に立っていたか。保存していれば渡せる
        //     - backupEligible (Boolean): クラウド同期対応か（Passkey の場合 true になる）
        //     - backedUp (Boolean): 実際にクラウドバックアップ済みか
        //     - AuthenticationExtensionsAuthenticatorOutputs: 拡張機能の出力
        //     - CollectedClientData: 認証フローでは不要
        //     - AuthenticationExtensionsClientOutputs: クライアント拡張機能の出力
        //     - Set<AuthenticatorTransport>: 通信方式（internal/usb/ble/nfc 等）
        //
        //   【今後の検討】 uvInitialized / backupEligible / backedUp を
        //                 登録時に保存しておき、認証時に渡すことで
        //                 セキュリティポリシー（Passkey 限定認証など）を実装できる
        CredentialRecordImpl credentialRecord = new CredentialRecordImpl(
            null,               // AttestationStatement（認証フローでは不要）
            null,               // uvInitialized（不明）
            null,               // backupEligible（不明）
            null,               // backedUp（不明）
            stored.signCount(), // counter: 前回の signCount。これより大きい値でないと検証失敗
            attestedCredData,   // AttestedCredentialData（公開鍵を含む）
            null,               // AuthenticationExtensionsAuthenticatorOutputs
            null,               // CollectedClientData
            null,               // AuthenticationExtensionsClientOutputs
            null                // Set<AuthenticatorTransport>
        );

        // AuthenticationRequest: ブラウザから受け取ったバイナリデータをまとめた入れ物。
        //   5 引数コンストラクタ: (credentialId, userHandle, authenticatorData, clientDataJSON, signature)
        AuthenticationRequest authRequest = new AuthenticationRequest(
            credentialIdBytes, userHandle, authenticatorData, clientDataJSON, signature
        );

        // ServerProperty: 登録時と同様にサーバーが期待する値を定義。
        ServerProperty serverProp = ServerProperty.builder()
            .origin(origin)
            .rpId(rpId)
            .challenge(new DefaultChallenge(B64_DEC.decode(challenge)))
            .build();

        // AuthenticationParameters:
        //   第 3 引数 null（allowCredentials）: 特定クレデンシャル ID に制限しない。
        //             すでに find() で credentialId を絞り込んでいるため問題なし。
        //   第 4 引数 true（userVerificationRequired）: UV フラグが必須
        //   第 5 引数 true（userPresenceRequired）: UP フラグが必須
        AuthenticationParameters authParams = new AuthenticationParameters(
            serverProp, credentialRecord, null, true, true
        );

        // ── webauthn4j による署名検証実行 ────────────────────────────────────
        // verify() は上記の検証ステップをすべて実行し、失敗すると例外をスローする。
        // 特に重要なのは:
        //   ① ECDSA 署名検証: signature が公開鍵で有効かどうか（偽造を防止）
        //   ② signCount のチェック: 前回より大きい値か（クローン検知）
        AuthenticationData authData = webAuthnManager.verify(authRequest, authParams);

        // 認証成功後の signCount を取り出す。呼び出し元で DB に書き戻す。
        // この値は stored.signCount() より必ず大きい（ライブラリが保証）。
        // 注意: 一部の実装（ソフトウェア認証器・クラウド同期 Passkey）では
        //       signCount が常に 0 を返すことがある。その場合クローン検知が機能しないが、
        //       webauthn4j は 0 を "カウンターを使わない" として許容する実装になっている。
        long newCount = authData.getAuthenticatorData().getSignCount();

        logger.info("authentication verified: userId={} credentialId={} newCount={}",
            stored.userId(), stored.credentialId(), newCount);

        // signCount だけ更新した新しいレコードを返す（イミュータブルレコードを再生成）
        return new CredentialRecord(
            stored.credentialId(),
            stored.userId(),
            stored.publicKeyCose(),  // 公開鍵は変わらない
            newCount,                // 更新された signCount
            stored.aaguid()
        );
    }
}
