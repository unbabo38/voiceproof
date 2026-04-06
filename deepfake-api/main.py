import tempfile
import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from detector import analyze

app = FastAPI(title="VoiceProof Deepfake Detector", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/detect")
async def detect(audio: UploadFile = File(...)):
    """
    音声ファイルを受け取り、AI生成音声かどうかを判定する

    Returns:
        score:      0.0(本物) 〜 1.0(AI生成)
        is_fake:    総合判定
        confidence: high / medium / low
        features:   各特徴量スコア (説明用)
    """
    ext = os.path.splitext(audio.filename or "")[-1].lower()
    if ext not in (".wav", ".mp3", ".webm", ".ogg", ".m4a", ".flac"):
        raise HTTPException(status_code=400, detail="対応フォーマット: wav, mp3, webm, ogg, m4a, flac")

    data = await audio.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="ファイルサイズは20MB以下にしてください")

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        result = analyze(tmp_path)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"音声の解析に失敗しました: {e}")
    finally:
        os.unlink(tmp_path)

    return {
        "score":      result.score,
        "is_fake":    result.is_fake,
        "threshold":  result.threshold,
        "confidence": result.confidence,
        "label":      "AI生成の疑い" if result.is_fake else "本物の音声",
        "features":   result.features,
    }
