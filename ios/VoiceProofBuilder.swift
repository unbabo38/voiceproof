// VoiceProof — Layer 2: データ構造 & 改ざん検知 ID 生成
//
// 「声紋ハッシュ + メッセージ + メタデータ」を結合し、
// コンテンツアドレス可能な一意 ID を生成する。
//
// 構造は Merkle Tree に近い:
//   leafA = SHA256(voiceHash)
//   leafB = SHA256(messageHash)
//   leafC = SHA256(metadata)
//   root  = SHA256(leafA ‖ leafB ‖ leafC)
//
// root が 1bit でも変われば全く別の ID になる。
// 検非違使が「この声でこの言葉を言っていない」を証明できる。

import Foundation
import CryptoKit
import CoreLocation

// MARK: - メッセージ証明パッケージ

struct VoiceProofPackage: Codable {

    // ── コアデータ ──
    let voiceHash:   String   // MFCC → SHA256 (hex)
    let messageHash: String   // メッセージテキスト → SHA256 (hex)
    let metadata:    ProofMetadata

    // ── Merkle ルート ──
    let proofID:     String   // = SHA256(leafA ‖ leafB ‖ leafC) (hex) — オンチェーンに刻むID

    // ── 読み取り専用 ──
    var summary: String {
        "VoiceProof[\(proofID.prefix(12))...] @ \(metadata.timestampISO)"
    }
}

struct ProofMetadata: Codable {
    let deviceID:    String
    let appVersion:  String
    let timestamp:   Int64      // Unix秒
    let latitude:    Double?
    let longitude:   Double?
    let locale:      String     // ja_JP 等 — 言語ごとのフォルマント差を考慮

    var timestampISO: String {
        ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: Double(timestamp)))
    }
}

// MARK: - ビルダー

enum VoiceProofBuilder {

    // MARK: パッケージ生成

    /// 声紋ハッシュ + メッセージ + メタデータから ProofID を生成する
    ///
    /// - Parameters:
    ///   - voiceprintResult: Layer 1 が返した声紋ハッシュ
    ///   - message:          ユーザーが発言した（またはテキスト入力した）内容
    ///   - location:         撮影位置（任意）
    /// - Returns: オンチェーンに登録する VoiceProofPackage
    static func build(
        voiceprintResult: VoiceprintResult,
        message:          String,
        location:         CLLocation? = nil
    ) -> VoiceProofPackage {

        // ── 1. 各リーフのハッシュ ──
        let leafA = sha256Hex(voiceprintResult.hash)

        let msgData = Data(message.utf8)
        let leafB   = sha256Hex(msgData)

        let meta = ProofMetadata(
            deviceID:   UIDevice.current.identifierForVendor?.uuidString ?? "unknown",
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0",
            timestamp:  Int64(Date().timeIntervalSince1970),
            latitude:   location?.coordinate.latitude,
            longitude:  location?.coordinate.longitude,
            locale:     Locale.current.identifier
        )
        let metaData = (try? JSONEncoder().encode(meta)) ?? Data()
        let leafC    = sha256Hex(metaData)

        // ── 2. Merkle ルート ──
        var combined = Data()
        combined.append(contentsOf: hexToData(leafA))
        combined.append(contentsOf: hexToData(leafB))
        combined.append(contentsOf: hexToData(leafC))
        let proofID = sha256Hex(combined)

        return VoiceProofPackage(
            voiceHash:   voiceprintResult.hashHex,
            messageHash: leafB,
            metadata:    meta,
            proofID:     proofID
        )
    }

    // MARK: 改ざん検知

    /// 既存パッケージのどこが変わったかを特定して返す
    ///
    ///   嘘松が「声は本物だが発言内容を差し替えた」ケースを検出できる
    static func detectTampering(
        package:    VoiceProofPackage,
        newVoice:   VoiceprintResult? = nil,
        newMessage: String? = nil
    ) -> TamperingReport {

        var issues: [TamperingIssue] = []

        // 声紋ハッシュが変わっていないか
        if let v = newVoice, v.hashHex != package.voiceHash {
            issues.append(.voiceMismatch(
                expected: package.voiceHash,
                actual:   v.hashHex
            ))
        }

        // メッセージハッシュが変わっていないか
        if let m = newMessage {
            let rehash = sha256Hex(Data(m.utf8))
            if rehash != package.messageHash {
                issues.append(.messageMismatch(
                    expected: package.messageHash,
                    actual:   rehash
                ))
            }
        }

        // proofID を再計算して一致確認
        if let v = newVoice, let m = newMessage {
            let rebuilt = build(voiceprintResult: v, message: m)
            if rebuilt.proofID != package.proofID {
                issues.append(.rootHashMismatch(
                    expected: package.proofID,
                    actual:   rebuilt.proofID
                ))
            }
        }

        return TamperingReport(packageID: package.proofID, issues: issues)
    }

    // MARK: ユーティリティ

    static func sha256Hex(_ data: Data) -> String {
        Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
    }

    static func hexToData(_ hex: String) -> Data {
        var data = Data()
        var idx  = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            if let byte = UInt8(hex[idx..<next], radix: 16) { data.append(byte) }
            idx = next
        }
        return data
    }
}

// MARK: - 改ざんレポート

struct TamperingReport {
    let packageID: String
    let issues:    [TamperingIssue]
    var isTampered: Bool { !issues.isEmpty }
}

enum TamperingIssue {
    case voiceMismatch(expected: String, actual: String)
    case messageMismatch(expected: String, actual: String)
    case rootHashMismatch(expected: String, actual: String)

    var description: String {
        switch self {
        case .voiceMismatch(let e, let a):
            return "声紋不一致: expected=\(e.prefix(8))… actual=\(a.prefix(8))…"
        case .messageMismatch(let e, let a):
            return "メッセージ不一致: expected=\(e.prefix(8))… actual=\(a.prefix(8))…"
        case .rootHashMismatch(let e, let a):
            return "ProofID不一致 (改ざん確定): expected=\(e.prefix(8))… actual=\(a.prefix(8))…"
        }
    }
}

// MARK: - 使用例

/*
 let recorder = VoiceprintRecorder()
 recorder.onComplete = { voiceprint in

     let package = VoiceProofBuilder.build(
         voiceprintResult: voiceprint,
         message: "昨日、渋谷で彼女とデートした",
         location: locationManager.location
     )
     // → package.proofID をコントラクトに書き込む
     print(package.summary)
     // VoiceProof[a3f9c2e14b8d...] @ 2026-04-03T10:00:00Z
 }
 try recorder.startRecording()
 // ... 数秒後 ...
 recorder.stopRecording()
*/
