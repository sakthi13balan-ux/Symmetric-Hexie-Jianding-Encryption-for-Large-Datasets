from flask import Flask, render_template, request, jsonify
import os, io
from sse_engine import engine

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024
UPLOAD = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD, exist_ok=True)


def extract_text(file_storage):
    name = file_storage.filename.lower()
    raw  = file_storage.read()

    if name.endswith('.txt') or name.endswith('.csv'):
        return raw.decode('utf-8', errors='ignore'), file_storage.filename

    if name.endswith('.pdf'):
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(raw)) as pdf:
                pages = [p.extract_text() or '' for p in pdf.pages]
            text = '\n'.join(pages)
            if len(text.strip()) > 20:
                return text, file_storage.filename
        except Exception:
            pass
        return raw.decode('latin-1', errors='ignore'), file_storage.filename

    if name.endswith('.docx'):
        try:
            import docx
            doc  = docx.Document(io.BytesIO(raw))
            text = '\n'.join(p.text for p in doc.paragraphs)
            return text, file_storage.filename
        except Exception:
            pass

    try:
        import re
        text = raw.decode('utf-8', errors='ignore')
        text = re.sub(r'<[^>]+>', ' ', text)
        return text, file_storage.filename
    except Exception:
        return '', file_storage.filename


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/setup', methods=['POST'])
def setup():
    d = request.json or {}
    return jsonify(engine.setup(d.get('sensitivity', 'normal')))


@app.route('/api/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'})
    f = request.files['file']
    if not f.filename:
        return jsonify({'status': 'error', 'message': 'Empty filename'})
    if not engine.master_key:
        return jsonify({'status': 'error', 'message': 'Initialize the system first'})
    text, fname = extract_text(f)
    if len(text.strip()) < 20:
        return jsonify({'status': 'error', 'message': 'Could not extract text — try a .txt file'})
    return jsonify(engine.ingest(text, fname))


# ── DELETE route — Backward Privacy ─────────────────────────────────────────
@app.route('/api/delete', methods=['POST'])
def delete():
    """
    Backward privacy: inserts op=1 (delete-flag) entries into the Jianding
    chain for every stem of the given doc_id.  The cloud server stores these
    entries identically to inserts (it cannot read the op flag).  Future
    searches will subtract this doc_id from result set S during decryption.

    Request body (JSON):
        { "doc_id": "doc001" }

    Response:
        {
          "status": "success",
          "doc_id": "doc001",
          "filename": "report.pdf",
          "entries_flagged": 47,
          "message": "Backward privacy: 47 op=1 delete entries inserted..."
        }
    """
    d      = request.json or {}
    doc_id = d.get('doc_id', '').strip()
    if not doc_id:
        return jsonify({'status': 'error', 'message': 'doc_id is required'})
    if not engine.master_key:
        return jsonify({'status': 'error', 'message': 'Initialize the system first'})
    return jsonify(engine.delete(doc_id))


@app.route('/api/search', methods=['POST'])
def search():
    d = request.json or {}
    q = d.get('query', '').strip()
    if not q:
        return jsonify({'status': 'error', 'message': 'Enter a search query'})
    if not engine.master_key:
        return jsonify({'status': 'error', 'message': 'Initialize the system first'})
    return jsonify(engine.smart_search(q))


@app.route('/api/stats')
def stats():
    return jsonify(engine.stats())


@app.route('/api/reset', methods=['POST'])
def reset():
    engine.reset()
    return jsonify({'status': 'success'})


if __name__ == '__main__':
    app.run(debug=True, port=5050)
