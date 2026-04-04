import 'dotenv/config';
import express from 'express';
import Stripe  from 'stripe';
import { ethers } from 'ethers';
import path from 'path';
import { fileURLToPath } from 'url';
import Redis from 'ioredis';
import rateLimit from 'express-rate-limit';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app    = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const PORT   = process.env.PORT || 3000;
const PRICE  = parseInt(process.env.PRICE_JPY || '300');

// ── Trust proxy for Railway ──────────────────────
app.set('trust proxy', 1);

// ── Redis ────────────────────────────────────────
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

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
app.use(express.static(path.join(__dirname, '..')));  // index.html を配信

// ── GET /health ──────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ ok: true });
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

// ── GET /api/status/:id ──────────────────────────────────
app.get('/api/status/:id', async (req, res) => {
  const raw = await redis.get(`results:${req.params.id}`);
  if (!raw) return res.json({ status: 'pending' });
  res.json({ status: 'confirmed', ...JSON.parse(raw) });
});

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
