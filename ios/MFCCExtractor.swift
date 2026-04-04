// VoiceProof — Layer 1: 声紋特徴量抽出 & ハッシュ化
// AVAudioEngine + Accelerate (vDSP) による MFCC 実装
//
// 「声帯は嘘をつかない。ブロックチェーンも嘘をつかない。
//   だからこの組み合わせは、21世紀の検非違使である。」

import AVFoundation
import Accelerate
import CryptoKit

// MARK: - MFCC パラメータ

struct MFCCConfig {
    let sampleRate:    Double = 44100
    let frameLength:   Int    = 1024    // FFT窓サイズ
    let hopLength:     Int    = 512     // フレームシフト
    let numMelFilters: Int    = 40      // Melフィルタバンク数
    let numCoeffs:     Int    = 13      // 出力するMFCC次元数
    let minFreq:       Double = 80      // 人声の最低周波数 (Hz)
    let maxFreq:       Double = 8000    // 人声の最高周波数 (Hz)
}

// MARK: - 録音 & 特徴量抽出

final class VoiceprintRecorder {

    private let engine    = AVAudioEngine()
    private let config    = MFCCConfig()
    private var frames:   [[Float]] = []   // 録音フレームバッファ
    private var isRecording = false

    // 録音完了後に呼ばれるコールバック
    var onComplete: ((VoiceprintResult) -> Void)?

    // MARK: - 録音制御

    func startRecording() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.record, mode: .measurement)
        try session.setActive(true)

        let inputNode = engine.inputNode
        let format    = inputNode.outputFormat(forBus: 0)

        inputNode.installTap(onBus: 0, bufferSize: AVAudioFrameCount(config.frameLength),
                             format: format) { [weak self] buffer, _ in
            self?.processBuffer(buffer)
        }

        frames = []
        isRecording = true
        try engine.start()
    }

    func stopRecording() {
        guard isRecording else { return }
        isRecording = false
        engine.inputNode.removeTap(onBus: 0)
        engine.stop()

        // フレームが集まったら MFCC を計算して結果を返す
        let mfccMatrix = frames.map { computeMFCC(frame: $0) }
        let result     = buildVoiceprintResult(from: mfccMatrix)
        onComplete?(result)
    }

    // MARK: - バッファ処理

    private func processBuffer(_ buffer: AVAudioPCMBuffer) {
        guard let channelData = buffer.floatChannelData?[0] else { return }
        let count  = Int(buffer.frameLength)
        let frame  = Array(UnsafeBufferPointer(start: channelData, count: count))
        // hop ごとに切り出してバッファに追加
        if frame.count >= config.frameLength {
            frames.append(Array(frame.prefix(config.frameLength)))
        }
    }

    // MARK: - MFCC 計算 (1フレーム分)

    private func computeMFCC(frame: [Float]) -> [Float] {

        // 1. ハミング窓を適用
        var windowed = applyHammingWindow(frame)

        // 2. FFT → パワースペクトル
        let powerSpectrum = computePowerSpectrum(&windowed)

        // 3. Mel フィルタバンク適用
        let melEnergies = applyMelFilterbank(powerSpectrum)

        // 4. log → DCT → MFCC 係数
        let logMel = melEnergies.map { logf(max($0, 1e-10)) }
        let mfcc   = dct(logMel, numCoeffs: config.numCoeffs)

        return mfcc
    }

    // MARK: - ハミング窓

    private func applyHammingWindow(_ frame: [Float]) -> [Float] {
        var result = frame
        let n = frame.count
        for i in 0..<n {
            let w = 0.54 - 0.46 * cos(2.0 * .pi * Float(i) / Float(n - 1))
            result[i] *= w
        }
        return result
    }

    // MARK: - FFT → パワースペクトル (vDSP)

    private func computePowerSpectrum(_ frame: inout [Float]) -> [Float] {
        let n    = frame.count
        let log2 = vDSP_Length(log2(Float(n)))
        guard let fftSetup = vDSP_create_fftsetup(log2, FFTRadix(FFT_RADIX2)) else {
            return [Float](repeating: 0, count: n / 2)
        }
        defer { vDSP_destroy_fftsetup(fftSetup) }

        var realPart = frame
        var imagPart = [Float](repeating: 0, count: n)

        realPart.withUnsafeMutableBufferPointer { rp in
            imagPart.withUnsafeMutableBufferPointer { ip in
                var splitComplex = DSPSplitComplex(realp: rp.baseAddress!,
                                                   imagp: ip.baseAddress!)
                vDSP_fft_zip(fftSetup, &splitComplex, 1, log2, FFTDirection(FFT_FORWARD))

                var power = [Float](repeating: 0, count: n / 2)
                vDSP_zvmags(&splitComplex, 1, &power, 1, vDSP_Length(n / 2))
                frame = power
            }
        }
        return frame
    }

    // MARK: - Mel フィルタバンク

    private func applyMelFilterbank(_ spectrum: [Float]) -> [Float] {
        let numBins  = spectrum.count
        let melMin   = hzToMel(config.minFreq)
        let melMax   = hzToMel(config.maxFreq)
        let melStep  = (melMax - melMin) / Double(config.numMelFilters + 1)

        // フィルタ中心周波数 (Hz)
        let centerFreqs: [Double] = (0..<config.numMelFilters + 2).map {
            melToHz(melMin + melStep * Double($0))
        }

        var melEnergies = [Float](repeating: 0, count: config.numMelFilters)

        for m in 0..<config.numMelFilters {
            let fLow    = centerFreqs[m]
            let fCenter = centerFreqs[m + 1]
            let fHigh   = centerFreqs[m + 2]

            for k in 0..<numBins {
                let freq = Double(k) * config.sampleRate / Double(config.frameLength)
                var weight: Double = 0
                if freq >= fLow && freq <= fCenter {
                    weight = (freq - fLow) / (fCenter - fLow)
                } else if freq > fCenter && freq <= fHigh {
                    weight = (fHigh - freq) / (fHigh - fCenter)
                }
                melEnergies[m] += spectrum[k] * Float(weight)
            }
        }
        return melEnergies
    }

    // MARK: - DCT (Discrete Cosine Transform)

    private func dct(_ input: [Float], numCoeffs: Int) -> [Float] {
        let n = input.count
        var output = [Float](repeating: 0, count: numCoeffs)
        for k in 0..<numCoeffs {
            var sum: Float = 0
            for m in 0..<n {
                sum += input[m] * cos(.pi * Float(k) * (Float(m) + 0.5) / Float(n))
            }
            output[k] = sum
        }
        return output
    }

    // MARK: - Mel ↔ Hz 変換

    private func hzToMel(_ hz: Double) -> Double { 2595 * log10(1 + hz / 700) }
    private func melToHz(_ mel: Double) -> Double { 700 * (pow(10, mel / 2595) - 1) }

    // MARK: - MFCC 行列 → VoiceprintResult

    private func buildVoiceprintResult(from mfccMatrix: [[Float]]) -> VoiceprintResult {
        guard !mfccMatrix.isEmpty else {
            return VoiceprintResult(meanMFCC: [], stdMFCC: [], hash: Data())
        }

        let numCoeffs = mfccMatrix[0].count
        let numFrames = Float(mfccMatrix.count)

        // 統計量: 平均 + 標準偏差 (= 声紋の "指紋")
        var mean = [Float](repeating: 0, count: numCoeffs)
        var std  = [Float](repeating: 0, count: numCoeffs)

        for frame in mfccMatrix {
            for i in 0..<numCoeffs { mean[i] += frame[i] }
        }
        for i in 0..<numCoeffs { mean[i] /= numFrames }

        for frame in mfccMatrix {
            for i in 0..<numCoeffs {
                let diff = frame[i] - mean[i]
                std[i] += diff * diff
            }
        }
        for i in 0..<numCoeffs { std[i] = sqrt(std[i] / numFrames) }

        // 特徴ベクトルを Data 化して SHA-256
        var featureData = Data()
        for v in mean + std {
            var bits = v.bitPattern.bigEndian
            featureData.append(contentsOf: withUnsafeBytes(of: &bits) { Data($0) })
        }
        let hash = Data(SHA256.hash(data: featureData))

        return VoiceprintResult(meanMFCC: mean, stdMFCC: std, hash: hash)
    }
}

// MARK: - 結果型

struct VoiceprintResult {
    let meanMFCC: [Float]   // 13次元の平均 MFCC
    let stdMFCC:  [Float]   // 13次元の標準偏差
    let hash:     Data      // SHA-256 (32 bytes) — これだけオンチェーンに刻む

    var hashHex: String {
        hash.map { String(format: "%02x", $0) }.joined()
    }
}
