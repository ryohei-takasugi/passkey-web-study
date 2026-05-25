package org.example.domain.model;

import io.vertx.core.json.JsonObject;

/**
 * 登録済み WebAuthn クレデンシャルを表す値オブジェクト。
 *
 * @param credentialId  クレデンシャルID（base64url）
 * @param userId        所有ユーザーID
 * @param publicKeyCose COSE 公開鍵（CBOR バイト列を base64url エンコード）
 * @param signCount     署名カウンター（リプレイ攻撃防止）
 * @param aaguid        認証器の AAGUID（UUID 文字列）
 */
public record CredentialRecord(
    String credentialId,
    String userId,
    String publicKeyCose,
    long   signCount,
    String aaguid
) {

    /**
     * JsonObject からインスタンスを生成する。
     *
     * @param json クレデンシャル JSON
     * @return CredentialRecord インスタンス
     */
    public static CredentialRecord fromJson(JsonObject json) {
        return new CredentialRecord(
            json.getString("credentialId"),
            json.getString("userId"),
            json.getString("publicKeyCose"),
            json.getLong("signCount", 0L),
            json.getString("aaguid", "00000000-0000-0000-0000-000000000000")
        );
    }

    /**
     * JsonObject に変換する。
     *
     * @return クレデンシャル JSON
     */
    public JsonObject toJson() {
        return new JsonObject()
            .put("credentialId",  credentialId)
            .put("userId",        userId)
            .put("publicKeyCose", publicKeyCose)
            .put("signCount",     signCount)
            .put("aaguid",        aaguid);
    }
}
