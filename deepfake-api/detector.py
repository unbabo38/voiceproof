"""
ディープフェイク音声検出モジュール

TTS/VC音声と自然音声の違いを複数の音響特徴量で検出する。
各スコアを重み付きアンサンブルで統合し 0.0〜1.0 のスコアを返す。
(0.0 = 本物寄り、1.0 = AI生成寄り)

特徴量:
  1. スペクトル平坦度    - TTS は均一になりやすい
  2. ピッチ一貫性       - AI音声はピッチ変動が不自然に滑らか
  3. MFCC 時系列変動    - 自然音声は変動が大きい
  4. フォルマント安定性  - TTS は F1/F2 が過度に安定する
  5. 無音区間パターン   - 自然音声は息継ぎ・ポーズが不規則
  6. ゼロ交差率分布     - AI音声は分布が狭い
"""

import numpy as np
import librosa
from dataclasses import dataclass


@dataclass
class DetectionResult:
    score: float              # 総合スコア (0.0=本物, 1.0=AI)
    is_fake: bool             # 判定 (score >= threshold)
    threshold: float
    features: dict            # 各特徴量スコア (デバッグ・説明用)
    confidence: str           # "high" / "medium" / "low"


THRESHOLD = 0.55
WEIGHTS = {
    "spectral_flatness":   0.20,
    "pitch_consistency":   0.25,
    "mfcc_variation":      0.20,
    "formant_stability":   0.15,
    "silence_pattern":     0.10,
    "zcr_distribution":    0.10,
}


def analyze(audio_path: str) -> DetectionResult:
    y, sr = librosa.load(audio_path, sr=16000, mono=True)

    features = {
        "spectral_flatness":  _spectral_flatness_score(y, sr),
        "pitch_consistency":  _pitch_consistency_score(y, sr),
        "mfcc_variation":     _mfcc_variation_score(y, sr),
        "formant_stability":  _formant_stability_score(y, sr),
        "silence_pattern":    _silence_pattern_score(y, sr),
        "zcr_distribution":   _zcr_distribution_score(y),
    }

    score = sum(features[k] * WEIGHTS[k] for k in features)
    score = float(np.clip(score, 0.0, 1.0))

    # スコアが閾値近辺 (±0.1) は信頼度低
    distance = abs(score - THRESHOLD)
    confidence = "high" if distance > 0.15 else "medium" if distance > 0.05 else "low"

    return DetectionResult(
        score=round(score, 4),
        is_fake=score >= THRESHOLD,
        threshold=THRESHOLD,
        features={k: round(v, 4) for k, v in features.items()},
        confidence=confidence,
    )


# ── 1. スペクトル平坦度 ────────────────────────────────────
def _spectral_flatness_score(y: np.ndarray, sr: int) -> float:
    """TTS音声は周波数分布が均一 → 平坦度が高い"""
    flatness = librosa.feature.spectral_flatness(y=y)[0]
    # 平均平坦度: 自然音声 ~0.01〜0.05, TTS ~0.05〜0.15
    mean_flat = float(np.mean(flatness))
    return float(np.clip(mean_flat * 10, 0.0, 1.0))


# ── 2. ピッチ一貫性 ────────────────────────────────────────
def _pitch_consistency_score(y: np.ndarray, sr: int) -> float:
    """
    AI音声はピッチ変動が滑らかすぎる (変動係数が小さい)
    自然音声は発話中に不規則な揺らぎがある
    """
    f0, _, _ = librosa.pyin(y, fmin=60, fmax=400, sr=sr)
    f0_voiced = f0[~np.isnan(f0)]
    if len(f0_voiced) < 10:
        return 0.5  # 判定不能

    cv = float(np.std(f0_voiced) / (np.mean(f0_voiced) + 1e-10))
    # 自然音声: cv ~0.10〜0.25, TTS: cv ~0.03〜0.10
    # cv が低いほど AI 寄り
    return float(np.clip(1.0 - cv * 5, 0.0, 1.0))


# ── 3. MFCC 時系列変動 ────────────────────────────────────
def _mfcc_variation_score(y: np.ndarray, sr: int) -> float:
    """
    自然音声は MFCC の時系列変動が大きい (感情・ためらい等)
    TTS は変動が均一になりやすい
    """
    mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
    # フレーム間の差分の標準偏差
    delta = np.diff(mfcc, axis=1)
    variation = float(np.mean(np.std(delta, axis=1)))
    # variation が低いほど AI 寄り
    return float(np.clip(1.0 - variation / 5.0, 0.0, 1.0))


# ── 4. フォルマント安定性 ─────────────────────────────────
def _formant_stability_score(y: np.ndarray, sr: int) -> float:
    """
    スペクトル重心の時系列変動でフォルマント安定性を近似
    TTS は F1/F2 が過度に安定する
    """
    centroid = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
    cv = float(np.std(centroid) / (np.mean(centroid) + 1e-10))
    # cv が低いほど安定 → AI 寄り
    return float(np.clip(1.0 - cv * 3, 0.0, 1.0))


# ── 5. 無音区間パターン ───────────────────────────────────
def _silence_pattern_score(y: np.ndarray, sr: int) -> float:
    """
    自然音声の息継ぎ・ポーズは不規則
    TTS は無音区間の長さが均一になりやすい
    """
    intervals = librosa.effects.split(y, top_db=30)
    if len(intervals) < 3:
        return 0.5

    gap_lengths = []
    for i in range(1, len(intervals)):
        gap = intervals[i][0] - intervals[i-1][1]
        gap_lengths.append(gap)

    cv = float(np.std(gap_lengths) / (np.mean(gap_lengths) + 1e-10))
    # gap の CV が低い (均一) = AI 寄り
    return float(np.clip(1.0 - cv, 0.0, 1.0))


# ── 6. ゼロ交差率分布 ─────────────────────────────────────
def _zcr_distribution_score(y: np.ndarray) -> float:
    """
    自然音声は ZCR の分布が広い
    TTS は ZCR が均一になりやすい
    """
    zcr = librosa.feature.zero_crossing_rate(y)[0]
    cv = float(np.std(zcr) / (np.mean(zcr) + 1e-10))
    return float(np.clip(1.0 - cv * 2, 0.0, 1.0))
