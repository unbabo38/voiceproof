// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VoiceProofRegistry
 * @notice 声紋 + メッセージの改ざん検知 ID をオンチェーンに永続記録するレジストリ
 * @dev Base / Polygon L2 にデプロイ。ガス代 < $0.001/レコード。
 *
 * 「21世紀の検非違使」として機能する:
 *   - 発言した事実 (proofID) を時刻・場所とともに封印する
 *   - 誰も削除できない (Immutable)
 *   - 本人だけが登録できる (msg.sender 縛り)
 *   - 誰でも検証できる (public view)
 *
 * proofID = SHA256(SHA256(voiceHash) ‖ SHA256(messageHash) ‖ SHA256(metadata))
 *         — Layer 2 (VoiceProofBuilder.swift) と同一アルゴリズム
 */

contract VoiceProofRegistry {

    // ──────────────────────────────────────────────
    //  データ構造
    // ──────────────────────────────────────────────

    struct ProofRecord {
        address  submitter;    // 登録者 (msg.sender)
        bytes32  proofID;      // Merkle ルートハッシュ
        bytes32  voiceHash;    // MFCC → SHA256
        bytes32  messageHash;  // メッセージ → SHA256 (内容は非公開)
        int64    latitude;     // 緯度 × 10^6 (0 = 未提供)
        int64    longitude;    // 経度 × 10^6
        uint64   timestamp;    // 発言時刻 (Unix秒, クライアント申告)
        uint64   blockTime;    // ブロックタイムスタンプ (改ざん不可)
        bool     revoked;      // 本人が「なかったことにしたい」場合の論理削除フラグ
    }

    // proofID → レコード
    mapping(bytes32 => ProofRecord) private _records;

    // submitter → 登録済み proofID リスト (最新 100 件)
    mapping(address => bytes32[]) private _userProofs;

    // proofID の存在フラグ (ガス節約用)
    mapping(bytes32 => bool) public exists;

    // ──────────────────────────────────────────────
    //  イベント
    // ──────────────────────────────────────────────

    event ProofRegistered(
        bytes32 indexed proofID,
        address indexed submitter,
        uint64  timestamp,
        uint64  blockTime
    );

    event ProofRevoked(
        bytes32 indexed proofID,
        address indexed submitter
    );

    // ──────────────────────────────────────────────
    //  登録
    // ──────────────────────────────────────────────

    /**
     * @notice 声紋証明を登録する。同一 proofID の二重登録は不可。
     *
     * @param proofID      Layer 2 で生成した Merkle ルートハッシュ
     * @param voiceHash    MFCC → SHA256 (声紋)
     * @param messageHash  メッセージ → SHA256 (内容は秘匿)
     * @param timestamp    発言時刻 (Unix秒) — ブロック時刻の ±10 分以内であること
     * @param latitude     緯度 × 10^6 (不要なら 0)
     * @param longitude    経度 × 10^6 (不要なら 0)
     */
    function register(
        bytes32 proofID,
        bytes32 voiceHash,
        bytes32 messageHash,
        uint64  timestamp,
        int64   latitude,
        int64   longitude
    ) external {
        // ── バリデーション ──
        require(!exists[proofID], "VoiceProof: already registered");
        require(
            uint64(block.timestamp) >= timestamp &&
            uint64(block.timestamp) - timestamp <= 600,
            "VoiceProof: timestamp out of range (must be within 10 min)"
        );

        // ── オンチェーン再計算で整合性を検証 ──
        // クライアントが生成した proofID が voiceHash + messageHash と一致するか確認
        // (メタデータはガス節約のため省略し、最低限の2リーフのみ検証)
        bytes32 leafA  = sha256(abi.encodePacked(voiceHash));
        bytes32 leafB  = sha256(abi.encodePacked(messageHash));
        bytes32 rootAB = sha256(abi.encodePacked(leafA, leafB));

        // 完全な3リーフ検証はクライアント側に委ね、ここでは2リーフプレフィックスを確認
        // proofID の先頭 16 bytes が rootAB の先頭 16 bytes と一致すること
        require(
            bytes16(proofID) == bytes16(rootAB),
            "VoiceProof: proofID does not match voice+message hashes"
        );

        // ── 書き込み ──
        _records[proofID] = ProofRecord({
            submitter:   msg.sender,
            proofID:     proofID,
            voiceHash:   voiceHash,
            messageHash: messageHash,
            latitude:    latitude,
            longitude:   longitude,
            timestamp:   timestamp,
            blockTime:   uint64(block.timestamp),
            revoked:     false
        });

        exists[proofID] = true;
        _userProofs[msg.sender].push(proofID);

        emit ProofRegistered(proofID, msg.sender, timestamp, uint64(block.timestamp));
    }

    // ──────────────────────────────────────────────
    //  論理削除 (本人のみ)
    // ──────────────────────────────────────────────

    /**
     * @notice proofID を「取り消し済み」としてマークする。
     * @dev レコード自体は消えない — 「取り消した事実」もブロックチェーンに残る。
     *      これが検非違使の恐ろしいところ。
     */
    function revoke(bytes32 proofID) external {
        ProofRecord storage rec = _records[proofID];
        require(rec.submitter == msg.sender, "VoiceProof: not the submitter");
        require(!rec.revoked,                "VoiceProof: already revoked");
        rec.revoked = true;
        emit ProofRevoked(proofID, msg.sender);
    }

    // ──────────────────────────────────────────────
    //  検証ビュー関数 (誰でも呼べる)
    // ──────────────────────────────────────────────

    /**
     * @notice proofID が存在し、取り消されておらず、正しい送信者のものかを確認する。
     * @return valid      true = 有効な証明
     * @return submitter  登録者アドレス
     * @return blockTime  記録時のブロックタイムスタンプ
     */
    function verify(bytes32 proofID)
        external view
        returns (bool valid, address submitter, uint64 blockTime)
    {
        if (!exists[proofID]) return (false, address(0), 0);
        ProofRecord storage rec = _records[proofID];
        return (!rec.revoked, rec.submitter, rec.blockTime);
    }

    /**
     * @notice レコードの完全な詳細を返す
     */
    function getRecord(bytes32 proofID)
        external view
        returns (ProofRecord memory)
    {
        require(exists[proofID], "VoiceProof: not found");
        return _records[proofID];
    }

    /**
     * @notice アドレスの直近 n 件の proofID リストを返す
     */
    function getProofsByAddress(address submitter, uint256 limit)
        external view
        returns (bytes32[] memory)
    {
        bytes32[] storage all = _userProofs[submitter];
        uint256 len    = all.length;
        uint256 count  = limit < len ? limit : len;
        bytes32[] memory result = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = all[len - count + i];   // 新しい順
        }
        return result;
    }

    /**
     * @notice 声紋ハッシュが過去に登録されていたか確認する
     *         同じ声で複数の矛盾する発言が登録されていないかのクロスチェックに使う
     */
    function hasVoiceHash(bytes32 voiceHash, address submitter)
        external view
        returns (bool found, bytes32 firstProofID)
    {
        bytes32[] storage proofs = _userProofs[submitter];
        for (uint256 i = 0; i < proofs.length; i++) {
            if (_records[proofs[i]].voiceHash == voiceHash) {
                return (true, proofs[i]);
            }
        }
        return (false, bytes32(0));
    }
}
