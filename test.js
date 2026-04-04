const crypto = require("crypto");

// ── Layer 1 の代わり: ダミーMFCCを声紋ハッシュとして生成 ──
function fakeMFCCHash(voiceLabel) {
  return crypto.createHash("sha256").update(`mfcc:${voiceLabel}`).digest();
}

// ── Layer 2: proofID 生成 (VoiceProofBuilder.swift と同じロジック) ──
function buildProofID(voiceHash, message, metadata) {
  const msgHash  = crypto.createHash("sha256").update(message, "utf8").digest();
  const metaHash = crypto.createHash("sha256").update(JSON.stringify(metadata)).digest();

  const leafA = crypto.createHash("sha256").update(voiceHash).digest();
  const leafB = crypto.createHash("sha256").update(msgHash).digest();
  const leafC = crypto.createHash("sha256").update(metaHash).digest();

  const proofID = crypto.createHash("sha256")
    .update(Buffer.concat([leafA, leafB, leafC]))
    .digest("hex");

  return { proofID, voiceHash: voiceHash.toString("hex"), messageHash: msgHash.toString("hex") };
}

// ── テスト ──
console.log("=== VoiceProof 動作確認 ===\n");

const meta = { deviceID: "iPhone-XYZ", timestamp: Math.floor(Date.now() / 1000), locale: "ja_JP" };

// 1. 通常ケース
const voice   = fakeMFCCHash("tanaka-voice");
const pkg     = buildProofID(voice, "昨日、渋谷で彼女とデートした", meta);
console.log("✅ proofID 生成:");
console.log("   proofID    :", pkg.proofID);
console.log("   voiceHash  :", pkg.voiceHash.slice(0, 16) + "...");
console.log("   messageHash:", pkg.messageHash.slice(0, 16) + "...");

// 2. メッセージを1文字変えると proofID が全く別になることを確認
const pkg2 = buildProofID(voice, "昨日、渋谷で友達とデートした", meta);
console.log("\n✅ メッセージ改ざん検知:");
console.log("   元のID  :", pkg.proofID.slice(0, 16) + "...");
console.log("   改ざん後:", pkg2.proofID.slice(0, 16) + "...");
console.log("   一致?   :", pkg.proofID === pkg2.proofID ? "❌ 同じ (バグ)" : "✅ 別ID (正常)");

// 3. 声紋が違うと proofID が変わることを確認
const voice2  = fakeMFCCHash("someone-else-voice");
const pkg3    = buildProofID(voice2, "昨日、渋谷で彼女とデートした", meta);
console.log("\n✅ 声紋差し替え検知:");
console.log("   元のID  :", pkg.proofID.slice(0, 16) + "...");
console.log("   別声紋後:", pkg3.proofID.slice(0, 16) + "...");
console.log("   一致?   :", pkg.proofID === pkg3.proofID ? "❌ 同じ (バグ)" : "✅ 別ID (正常)");

// 4. 同じ入力なら必ず同じ proofID (決定論的)
const pkg4 = buildProofID(voice, "昨日、渋谷で彼女とデートした", meta);
console.log("\n✅ 再現性:");
console.log("   1回目:", pkg.proofID.slice(0, 16) + "...");
console.log("   2回目:", pkg4.proofID.slice(0, 16) + "...");
console.log("   一致?:", pkg.proofID === pkg4.proofID ? "✅ 同じ (正常)" : "❌ 違う (バグ)");
