import 'dotenv/config';
import express from 'express';
import Stripe  from 'stripe';
import { ethers } from 'ethers';
import path from 'path';
import { fileURLToPath } from 'url';
import Redis from 'ioredis';
import rateLimit from 'express-rate-limit';
import { Storage } from '@google-cloud/storage';
import multer from 'multer';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app    = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const PORT   = process.env.PORT || 3000;
const PRICE  = parseInt(process.env.PRICE_JPY || '300');

// ── Trust proxy for Railway ──────────────────────
app.set('trust proxy', 1);

// ── Redis ────────────────────────────────────────
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// ── GCS ─────────────────────────────────────────
const gcsCredentials = JSON.parse(process.env.GCS_CREDENTIALS || '{}');
const storage = new Storage({ credentials: gcsCredentials });
const bucket  = storage.bucket(process.env.GCS_BUCKET || 'voiceproof-audio');
const upload  = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

// ── Contract ────────────────────────────────────────────
const ABI = [
  "function record(bytes32 voiceHash, uint64 timestamp, int64 latitude, int64 longitude) external",
  "function verify(bytes32 voiceHash) external view returns (bool valid, address submitter, uint64 blockTime)",
  "function exists(bytes32) external view returns (bool)",
  "function getUserRecords(address user) external view returns (bytes32[] memory)",
];

const provider = new ethers.JsonRpcProvider(
  process.env.RPC_URL || 'https://sepolia.base.org'
);
const rawKey   = (process.env.PRIVATE_KEY || '').trim().replace(/^["']|["']$/g, '');
console.log('[init] PRIVATE_KEY length:', rawKey.length, 'starts with 0x:', rawKey.startsWith('0x'));
const wallet   = new ethers.Wallet(rawKey, provider);
const contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, ABI, wallet);

// ── Nonce cache (parallel tx prevention) ────────
let nonce = null;

// ── Rate limiter for /api/pay ────────────────────
const payLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Middleware ──────────────────────────────────────────
// Stripe webhook は raw body が必要なので先に登録
app.post('/api/webhook',
  express.raw({ type: 'application/json' }),
  handleWebhook
);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));  // index.html を配信

// ── GET /health ──────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

// ── JWT ミドルウェア ──────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
function authRequired(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
}

// ── POST /api/signup ─────────────────────────────
// アカウント登録と同時に声紋を取得する
// 事前に GET /api/auth/challenge でチャレンジを取得し、読み上げた音声の embedding を送る
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, embedding, challengeId, transcript } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    if (!Array.isArray(embedding) || embedding.length === 0)
      return res.status(400).json({ error: 'embedding required — 声紋の登録が必要です' });
    if (!challengeId)
      return res.status(400).json({ error: 'challengeId required — GET /api/auth/challenge で取得してください' });

    // チャレンジ検証
    const challengeErr = await validateChallenge(challengeId, transcript);
    if (challengeErr) return res.status(401).json({ error: challengeErr });

    // ユーザー重複チェック
    const exists = await redis.get(`user:${email}`);
    if (exists) return res.status(409).json({ error: 'email already registered' });

    // ユーザー作成
    const hash   = await bcrypt.hash(password, 10);
    const userId = randomUUID();
    await redis.set(`user:${email}`, JSON.stringify({ userId, email, passwordHash: hash }));

    // 声紋保存
    await redis.set(`voiceprint:${userId}`, JSON.stringify({
      vector:    embedding,
      count:     1,
      updatedAt: new Date().toISOString(),
    }));

    const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email, message: '登録完了 — 声紋を記録しました' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/login ──────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const raw = await redis.get(`user:${email}`);
    if (!raw) return res.status(401).json({ error: 'invalid email or password' });
    const user = JSON.parse(raw);
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid email or password' });
    const token = jwt.sign({ userId: user.userId, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, email });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/upload ─────────────────────────────
// 音声ファイルをGCSにアップロードしてURLを返す
app.post('/api/upload', authRequired, upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'audio file required' });
    const { voiceHash } = req.body;
    if (!voiceHash) return res.status(400).json({ error: 'voiceHash required' });

    const filename = `${req.user.userId}/${voiceHash}.webm`;
    const file = bucket.file(filename);
    await file.save(req.file.buffer, {
      contentType: 'audio/webm',
      metadata: { voiceHash, uploadedAt: new Date().toISOString() },
    });
    const [signedUrl] = await file.getSignedUrl({
      action: 'read',
      expires: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7日間有効
    });

    // Redisにユーザーごとに保存（embeddingも含む）
    const record = {
      gcsUrl: signedUrl,
      transcript: req.body.transcript || '',
      uploadedAt: new Date().toISOString(),
      voiceHash,
      embedding: req.body.embedding ? JSON.parse(req.body.embedding) : null,
    };
    await redis.set(`audio:${req.user.userId}:${voiceHash}`, JSON.stringify(record));
    await redis.lpush(`records:${req.user.userId}`, voiceHash);

    res.json({ gcsUrl: signedUrl });
  } catch(e) {
    console.error('/api/upload error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/pay ────────────────────────────────────────
// フロントから voiceHash・位置・時刻を受け取り PaymentIntent を作成
app.post('/api/pay', payLimiter, async (req, res) => {
  try {
    const { voiceHash, timestamp, latitude = 0, longitude = 0, transcript = '' } = req.body;
    if (!voiceHash) return res.status(400).json({ error: 'voiceHash required' });

    // 既に記録済みかチェック (二重課金防止)
    const hashBytes = toBytes32(voiceHash);
    const alreadyExists = await contract.exists(hashBytes);
    if (alreadyExists) return res.status(409).json({ error: 'already recorded on chain' });

    const intent = await stripe.paymentIntents.create({
      amount:   PRICE,
      currency: 'jpy',
      metadata: {
        voiceHash,
        timestamp:  String(timestamp),
        latitude:   String(latitude),
        longitude:  String(longitude),
        transcript: transcript.slice(0, 500),
      },
    });

    await redis.set(
      `pending:${intent.id}`,
      JSON.stringify({ voiceHash, timestamp, latitude, longitude }),
      'EX', 3600
    );

    res.json({
      clientSecret:    intent.client_secret,
      paymentIntentId: intent.id,
      publishableKey:  process.env.STRIPE_PUBLISHABLE_KEY,
    });
  } catch(e) {
    console.error('/api/pay error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/pay/dev ────────────────────────────────────
// Stripe スキップ用テストエンドポイント
app.post('/api/pay/dev', async (req, res) => {
  try {
    const { voiceHash, timestamp } = req.body;
    if (!voiceHash) return res.status(400).json({ error: 'voiceHash required' });
    const intentId = 'dev_' + Date.now();
    await submitToChain(intentId, { voiceHash, timestamp, latitude: 0, longitude: 0 });
    const raw = await redis.get(`results:${intentId}`);
    if (!raw) return res.status(500).json({ error: 'chain write failed' });
    res.json({ paymentIntentId: intentId, ...JSON.parse(raw) });
  } catch(e) {
    console.error('/api/pay/dev error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/records ─────────────────────────────────────
app.get('/api/records', authRequired, async (req, res) => {
  try {
    const hashes = await redis.lrange(`records:${req.user.userId}`, 0, -1);
    const records = await Promise.all(hashes.map(async voiceHash => {
      const raw = await redis.get(`audio:${req.user.userId}:${voiceHash}`);
      if (!raw) return null;
      const data = JSON.parse(raw);
      try {
        const hashBytes = toBytes32(voiceHash);
        const [valid, , blockTime] = await contract.verify(hashBytes);
        data.onChain = valid;
        data.blockTime = blockTime > 0n ? new Date(Number(blockTime) * 1000).toISOString() : null;
      } catch { data.onChain = false; }
      return data;
    }));
    res.json(records.filter(Boolean).sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt)));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/status/:id ──────────────────────────────────
app.get('/api/status/:id', async (req, res) => {
  const raw = await redis.get(`results:${req.params.id}`);
  if (!raw) return res.json({ status: 'pending' });
  res.json({ status: 'confirmed', ...JSON.parse(raw) });
});

// ── GET /api/embedding/:hash ─────────────────────────────
app.get('/api/embedding/:hash', authRequired, async (req, res) => {
  const raw = await redis.get(`audio:${req.user.userId}:${req.params.hash}`);
  if (!raw) return res.status(404).json({ error: 'not found' });
  const { embedding } = JSON.parse(raw);
  if (!embedding) return res.status(404).json({ error: 'embedding not saved' });
  res.json({ embedding });
});

// ── GET /api/auth/challenge ───────────────────────────────
// ログイン時に読み上げさせるランダム文字列を発行する
// 有効期限: 90秒。期限切れ or 未使用なら verify で弾く
// 3文字以上・音が被らない単語に絞る
// 数字読みと被らない単語のみ使用 (に/ご/さん/はち等を含まない)
const CHALLENGE_WORDS = [
  'さくら','あおぞら','しろくま','やまびこ',
  'たいよう','かすみ','つばさ','ほたる',
  'あらしま','とまれ','すだち','わたぐも',
];

// 数字は1桁×3つに分けて読ませる (「さん・はち・いち」形式)
// 音声認識が4桁をひらがな/漢字に変換するのを回避
function makeChallenge() {
  const pick = () => CHALLENGE_WORDS[Math.floor(Math.random() * CHALLENGE_WORDS.length)];
  const d = () => Math.floor(Math.random() * 10);
  const digits = [d(), d(), d()];   // 例: [3, 8, 1]
  const text   = `${pick()} ${digits.join(' ')} ${pick()}`;  // "さくら 3 8 1 ひかり"
  return { text, digits };
}

// 日本語数字→算用数字 変換 (長い語から順に適用して誤変換を防ぐ)
const JP_NUM_REPLACEMENTS = [
  // かな (長い語を先に)
  ['きゅう','9'],['ゼロ','0'],['まる','0'],['いち','1'],
  ['さん','3'],['よん','4'],['ろく','6'],['なな','7'],['しち','7'],['はち','8'],
  // かな単体 (短いので後回し)
  ['に','2'],['ご','5'],
  // 漢字
  ['零','0'],['〇','0'],['一','1'],['二','2'],['三','3'],
  ['四','4'],['五','5'],['六','6'],['七','7'],['八','8'],['九','9'],
  // 全角数字
  ['０','0'],['１','1'],['２','2'],['３','3'],['４','4'],
  ['５','5'],['６','6'],['７','7'],['８','8'],['９','9'],
];

function extractDigits(transcript) {
  if (!transcript) return [];
  let text = transcript.normalize('NFKC');
  for (const [word, digit] of JP_NUM_REPLACEMENTS) {
    text = text.replaceAll(word, digit);
  }
  return (text.match(/[0-9]/g) || []).map(Number);
}

app.get('/api/auth/challenge', async (req, res) => {
  const challengeId  = randomUUID();
  const { text, digits } = makeChallenge();
  await redis.set(`challenge:${challengeId}`, JSON.stringify({ text, digits }), 'EX', 90);
  res.json({ challengeId, text, expiresIn: 90 });
});

// ── チャレンジ検証ヘルパー ────────────────────────────────
// 成功時は null、失敗時はエラーメッセージを返す
async function validateChallenge(challengeId, transcript) {
  const raw = await redis.get(`challenge:${challengeId}`);
  if (!raw) return 'チャレンジが無効または期限切れです (90秒以内に読み上げてください)';

  const { text, digits } = JSON.parse(raw);
  const spoken = extractDigits(transcript);

  if (spoken.length < digits.length)
    return `数字が読み取れませんでした。「${text}」をはっきり読み上げてください (認識: "${transcript ?? ''}")`;

  const matched = digits.every((d, i) => spoken[i] === d);
  if (!matched)
    return `数字が一致しません。「${text}」をそのまま読み上げてください (認識した数字: ${spoken.join(' ')})`;

  await redis.del(`challenge:${challengeId}`);
  return null;
}

// ── POST /api/auth/verify ─────────────────────────────────
// チャレンジ文字列を読んだ音声で声紋認証 → JWT 発行
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { challengeId, embedding, transcript, email } = req.body;
    if (!challengeId || !Array.isArray(embedding) || !email)
      return res.status(400).json({ error: 'challengeId, embedding, email が必要です' });

    // 1. チャレンジの有効性確認
    const expectedText = await redis.get(`challenge:${challengeId}`);
    if (!expectedText)
      return res.status(401).json({ error: 'チャレンジが無効または期限切れです (90秒以内に読み上げてください)' });

    // 2. テキスト一致チェック (数字部分は必須、単語はゆらぎを許容)
    const expectedNum = expectedText.match(/\d+/)?.[0] ?? '';
    const actualNum   = (transcript ?? '').replace(/\s/g, '').match(/\d+/)?.[0] ?? '';
    if (expectedNum && actualNum !== expectedNum)
      return res.status(401).json({
        error: `読み上げ内容が一致しません (期待: "${expectedText}")`,
        hint:  '画面の文字列をそのまま読み上げてください',
      });

    // 3. 声紋認証
    const userRaw = await redis.get(`user:${email}`);
    if (!userRaw) return res.status(404).json({ error: 'ユーザーが見つかりません' });
    const { userId } = JSON.parse(userRaw);

    const vpRaw = await redis.get(`voiceprint:${userId}`);
    if (!vpRaw)
      return res.status(401).json({ error: '声紋が未登録です。先に /api/enroll を完了してください' });

    const { vector: registered, count: sampleCount } = JSON.parse(vpRaw);
    const similarity = cosineSimilarity(registered, embedding);
    const THRESHOLD  = 0.82;

    // 使用済みチャレンジは即削除 (リプレイ攻撃防止)
    await redis.del(`challenge:${challengeId}`);

    if (similarity < THRESHOLD)
      return res.status(401).json({
        error:      `声紋が一致しません (類似度: ${(similarity * 100).toFixed(1)}%)`,
        similarity: Math.round(similarity * 10000) / 10000,
        threshold:  THRESHOLD,
      });

    // 4. JWT 発行
    const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      email,
      similarity:  Math.round(similarity * 10000) / 10000,
      sampleCount,
      message:     `声紋認証成功 (類似度: ${(similarity * 100).toFixed(1)}%)`,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/enroll ──────────────────────────────────────
// 声紋を登録する (チャレンジ文字列の読み上げ必須)
// 複数回登録すると平均ベクトルで更新される (少なくとも3回推奨)
app.post('/api/enroll', authRequired, async (req, res) => {
  try {
    const { embedding, challengeId, transcript } = req.body;
    if (!Array.isArray(embedding) || embedding.length === 0)
      return res.status(400).json({ error: 'embedding (array) required' });
    if (!challengeId)
      return res.status(400).json({ error: 'challengeId required — GET /api/auth/challenge で取得してください' });

    // チャレンジ検証
    const challengeErr = await validateChallenge(challengeId, transcript);
    if (challengeErr) return res.status(401).json({ error: challengeErr });

    const key = `voiceprint:${req.user.userId}`;
    const existing = await redis.get(key);

    let stored;
    if (existing) {
      // 既存の登録声紋と平均を取り移動平均で更新
      const prev = JSON.parse(existing);
      const count = prev.count + 1;
      const avg = prev.vector.map((v, i) => (v * prev.count + embedding[i]) / count);
      stored = { vector: avg, count, updatedAt: new Date().toISOString() };
    } else {
      stored = { vector: embedding, count: 1, updatedAt: new Date().toISOString() };
    }

    await redis.set(key, JSON.stringify(stored));

    res.json({
      enrolled: true,
      sampleCount: stored.count,
      message: stored.count < 3
        ? `登録完了 (精度向上のためあと${3 - stored.count}回の登録を推奨します)`
        : '声紋登録が完了しました',
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── POST /api/verify-speaker ──────────────────────────────
// 提出された embedding が登録済み声紋と同一人物かを判定する
// 認証済みでも未認証ユーザーの声紋確認にも使えるよう subject_id を受け取る設計
app.post('/api/verify-speaker', authRequired, async (req, res) => {
  try {
    const { embedding, subjectId } = req.body;
    if (!Array.isArray(embedding) || embedding.length === 0)
      return res.status(400).json({ error: 'embedding (array) required' });

    // subjectId 未指定なら自分自身の声紋と比較
    const targetId = subjectId || req.user.userId;
    const raw = await redis.get(`voiceprint:${targetId}`);
    if (!raw) return res.status(404).json({ error: '声紋が未登録です。先に /api/enroll を実行してください' });

    const { vector: registered, count: sampleCount } = JSON.parse(raw);

    if (registered.length !== embedding.length)
      return res.status(400).json({ error: `次元数が一致しません (登録: ${registered.length}, 提出: ${embedding.length})` });

    const similarity = cosineSimilarity(registered, embedding);
    const THRESHOLD  = 0.82; // 実測調整推奨
    const isAuthentic = similarity >= THRESHOLD;

    res.json({
      isAuthentic,
      similarity:   Math.round(similarity * 10000) / 10000,
      threshold:    THRESHOLD,
      sampleCount,
      detail: isAuthentic
        ? `本人の声と確認されました (類似度: ${(similarity * 100).toFixed(1)}%)`
        : `声紋が一致しません (類似度: ${(similarity * 100).toFixed(1)}% < 閾値 ${(THRESHOLD * 100).toFixed(0)}%)`,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── GET /api/voiceprint/status ────────────────────────────
// 声紋の登録状況を確認する
app.get('/api/voiceprint/status', authRequired, async (req, res) => {
  const raw = await redis.get(`voiceprint:${req.user.userId}`);
  if (!raw) return res.json({ enrolled: false });
  const { count, updatedAt } = JSON.parse(raw);
  res.json({ enrolled: true, sampleCount: count, updatedAt, ready: count >= 3 });
});

// ── コサイン類似度 ────────────────────────────────────────
function cosineSimilarity(a, b) {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot   += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : Math.max(0, Math.min(1, dot / denom));
}

// ── GET /api/proof/:hash ─────────────────────────────────
app.get('/api/proof/:hash', async (req, res) => {
  try {
    const hashBytes = toBytes32(req.params.hash);
    const [valid, submitter, blockTime] = await contract.verify(hashBytes);
    res.json({
      valid,
      submitter,
      blockTime:    Number(blockTime),
      blockTimeISO: blockTime > 0n ? new Date(Number(blockTime) * 1000).toISOString() : null,
      explorerUrl:  `https://sepolia.basescan.org/address/${process.env.CONTRACT_ADDRESS}`,
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Stripe Webhook ───────────────────────────────────────
async function handleWebhook(req, res) {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch(e) {
    console.error('Webhook signature failed:', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const intent = event.data.object;
    const raw    = await redis.get(`pending:${intent.id}`);
    if (raw) await submitToChain(intent.id, JSON.parse(raw));
  }

  res.json({ received: true });
}

// ── チェーンへの書き込み ─────────────────────────────────
async function submitToChain(intentId, data) {
  const { voiceHash, latitude, longitude } = data;
  try {
    console.log(`[chain] submitting voiceHash=${voiceHash.slice(0,16)}...`);

    // nonce を手動管理して並列 tx 衝突を防ぐ
    if (nonce === null) nonce = await provider.getTransactionCount(wallet.address);

    // チェーンの現在時刻を使う (クライアント時刻はブロックタイムと合わない)
    const block = await provider.getBlock('latest');
    const chainTimestamp = BigInt(block.timestamp);

    const tx = await contract.record(
      toBytes32(voiceHash),
      chainTimestamp,
      BigInt(Math.round((latitude  || 0) * 1_000_000)),
      BigInt(Math.round((longitude || 0) * 1_000_000)),
      { nonce: nonce++ }
    );

    console.log(`[chain] tx sent: ${tx.hash}`);
    const receipt = await tx.wait();
    console.log(`[chain] confirmed block #${receipt.blockNumber}`);

    await redis.set(
      `results:${intentId}`,
      JSON.stringify({
        txHash:      receipt.hash,
        blockNumber: receipt.blockNumber,
        confirmedAt: new Date().toISOString(),
        explorerUrl: `https://sepolia.basescan.org/tx/${receipt.hash}`,
      }),
      'EX', 86400
    );
    await redis.del(`pending:${intentId}`);
  } catch(e) {
    console.error('[chain] TX failed:', e.message);
    nonce = null; // エラー時はリセット
  }
}

// ── ユーティリティ ───────────────────────────────────────
function toBytes32(hex) {
  const clean = hex.replace(/^0x/, '').slice(0, 64).padEnd(64, '0');
  return '0x' + clean;
}

// ── 起動 ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🎙 VoiceProof Server`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Contract: ${process.env.CONTRACT_ADDRESS}`);
  console.log(`   Wallet:   ${wallet.address}`);
  console.log(`   Price:    ¥${PRICE}/回\n`);
});
