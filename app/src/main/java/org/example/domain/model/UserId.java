package org.example.domain.model;

/**
 * ユーザーを一意に識別する値オブジェクト。
 *
 * @param value ユーザーID文字列
 */
public record UserId(String value) {

    /**
     * 文字列からインスタンスを生成する。
     *
     * @param value ユーザーID文字列
     * @return UserId インスタンス
     */
    public static UserId of(String value) {
        return new UserId(value);
    }
}
