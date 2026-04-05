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

// MARK: - サーバー通信

/// verify-speaker / enroll の結果
struct SpeakerVerificationResult {
    let isAuthentic:  Bool
    let similarity:   Double
    let threshold:    Double
    let sampleCount:  Int
    let detail:       String
}

enum VoiceProofAPI {

    static var baseURL: String = "https://your-server.railway.app"  // ← 環境に合わせて変更
    static var jwtToken: String = ""                                  // ← ログイン後にセット

    // MARK: チャレンジ取得
    /// ログイン画面で「この文字列を読んでください」と表示するテキストを取得する
    static func fetchChallenge() async throws -> (challengeId: String, text: String, expiresIn: Int) {
        guard let url = URL(string: baseURL + "/api/auth/challenge") else { throw URLError(.badURL) }
        let (data, _) = try await URLSession.shared.data(from: url)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URLError(.cannotParseResponse)
        }
        return (
            challengeId: json["challengeId"] as? String ?? "",
            text:        json["text"]        as? String ?? "",
            expiresIn:   json["expiresIn"]   as? Int    ?? 90
        )
    }

    // MARK: チャレンジ声紋認証 → JWT 取得
    /// チャレンジ文字列を読んだ録音で声紋認証し、成功したら JWT を返す
    static func verifyChallenge(
        challengeId: String,
        result:      VoiceprintResult,
        transcript:  String,
        email:       String
    ) async throws -> String {   // JWT token
        let embedding = result.meanMFCC + result.stdMFCC
        return try await _post(
            path: "/api/auth/verify",
            body: [
                "challengeId": challengeId,
                "embedding":   embedding,
                "transcript":  transcript,
                "email":       email,
            ],
            parse: { json in
                guard let token = json["token"] as? String else {
                    let msg = json["error"] as? String ?? "認証失敗"
                    throw NSError(domain: "VoiceProofAPI", code: 401,
                                  userInfo: [NSLocalizedDescriptionKey: msg])
                }
                return token
            }
        )
    }

    // MARK: 声紋登録
    /// iOS の VoiceprintResult を /api/enroll に送信する
    static func enroll(result: VoiceprintResult) async throws -> (sampleCount: Int, message: String) {
        let embedding = result.meanMFCC + result.stdMFCC   // 26次元
        return try await _post(
            path: "/api/enroll",
            body: ["embedding": embedding],
            parse: { json in
                let count   = json["sampleCount"] as? Int    ?? 0
                let message = json["message"]     as? String ?? ""
                return (count, message)
            }
        )
    }

    // MARK: 話者認証
    /// 録音した音声が登録済みの本人かを確認する
    /// - Returns: SpeakerVerificationResult
    static func verifySpeaker(result: VoiceprintResult) async throws -> SpeakerVerificationResult {
        let embedding = result.meanMFCC + result.stdMFCC
        return try await _post(
            path: "/api/verify-speaker",
            body: ["embedding": embedding],
            parse: { json in
                SpeakerVerificationResult(
                    isAuthentic: json["isAuthentic"] as? Bool   ?? false,
                    similarity:  json["similarity"]  as? Double ?? 0,
                    threshold:   json["threshold"]   as? Double ?? 0,
                    sampleCount: json["sampleCount"] as? Int    ?? 0,
                    detail:      json["detail"]      as? String ?? ""
                )
            }
        )
    }

    // MARK: 内部: POST ヘルパー
    private static func _post<T>(
        path: String,
        body: [String: Any],
        parse: @escaping ([String: Any]) throws -> T
    ) async throws -> T {
        guard let url = URL(string: baseURL + path) else {
            throw URLError(.badURL)
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json",    forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(jwtToken)",  forHTTPHeaderField: "Authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw URLError(.cannotParseResponse)
        }
        if !(200..<300).contains(http.statusCode) {
            let msg = json["error"] as? String ?? "HTTP \(http.statusCode)"
            throw NSError(domain: "VoiceProofAPI", code: http.statusCode,
                          userInfo: [NSLocalizedDescriptionKey: msg])
        }
        return try parse(json)
    }
}

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

    // MARK: 認証付きパッケージ生成

    /// 話者認証を通過した場合のみ VoiceProofPackage を返す
    ///
    /// - Throws: `VoiceProofError.speakerMismatch` — 声紋が登録済みと一致しない
    /// - Throws: `VoiceProofError.notEnrolled`    — 声紋が未登録
    static func buildWithVerification(
        voiceprintResult: VoiceprintResult,
        message:          String,
        location:         CLLocation? = nil
    ) async throws -> (package: VoiceProofPackage, verification: SpeakerVerificationResult) {

        let verification = try await VoiceProofAPI.verifySpeaker(result: voiceprintResult)

        guard verification.isAuthentic else {
            throw VoiceProofError.speakerMismatch(
                similarity: verification.similarity,
                threshold:  verification.threshold,
                detail:     verification.detail
            )
        }

        let package = build(
            voiceprintResult: voiceprintResult,
            message:          message,
            location:         location
        )
        return (package, verification)
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

// MARK: - エラー型

enum VoiceProofError: LocalizedError {
    case speakerMismatch(similarity: Double, threshold: Double, detail: String)
    case notEnrolled

    var errorDescription: String? {
        switch self {
        case .speakerMismatch(let sim, let thr, let detail):
            return "声紋が一致しません (類似度: \(Int(sim*100))% < 閾値 \(Int(thr*100))%) — \(detail)"
        case .notEnrolled:
            return "声紋が未登録です。先に登録を完了してください"
        }
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
 // ── 声紋登録 (初回・複数回実行で精度向上) ──
 VoiceProofAPI.baseURL  = "https://your-server.railway.app"
 VoiceProofAPI.jwtToken = authToken   // ログイン後のJWT

 let recorder = VoiceprintRecorder()
 recorder.onComplete = { voiceprint in
     Task {
         let (count, msg) = try await VoiceProofAPI.enroll(result: voiceprint)
         print("登録完了: \(msg) (サンプル数: \(count))")
     }
 }
 try recorder.startRecording()

 // ── 認証付き証明パッケージ生成 ──
 recorder.onComplete = { voiceprint in
     Task {
         do {
             let (package, verification) = try await VoiceProofBuilder.buildWithVerification(
                 voiceprintResult: voiceprint,
                 message: "昨日、渋谷で彼女とデートした",
                 location: locationManager.location
             )
             // verification.similarity → 0.94 など
             // package.proofID をコントラクトに書き込む
             print(package.summary)
             // VoiceProof[a3f9c2e14b8d...] @ 2026-04-03T10:00:00Z

         } catch VoiceProofError.speakerMismatch(let sim, _, _) {
             print("声紋不一致 (類似度: \(Int(sim*100))%) — 別の話者か偽音声の疑い")
         }
     }
 }
*/
