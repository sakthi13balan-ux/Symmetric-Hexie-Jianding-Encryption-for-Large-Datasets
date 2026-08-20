"""
SSE Engine — Hexie + Jianding
Includes:
  • Proper HMAC-SHA256 PRF with full 32-byte output split
  • AES-128 (normal) / AES-256 (sensitive) adaptive encryption
  • Real text preprocessing: lowercase, stop-word removal, stemming
  • Automatic search fallback: exact → fuzzy (edit-dist ≤1) → semantic
  • Multi-keyword: detected from query string (AND / OR / comma)
  • Ranked results via TF-IDF embedded in ciphertext
  • Document snippet / context returned for every result
  • Jianding MAC chain always on — verified flag on every search
  • DELETE operation — backward privacy (op=1 flag in chain)
"""

import os, re, hashlib, math, time
from collections import defaultdict
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import struct

# ── Stop words ──────────────────────────────────────────────────────────────
STOP = {
    'the','and','for','are','was','were','this','that','with','from','have',
    'has','had','its','not','but','also','can','been','will','into','more',
    'than','they','their','which','about','would','could','should','when',
    'what','how','who','all','any','each','both','few','our','your','him',
    'her','his','she','you','over','such','even','after','before','between',
    'same','other','may','well','just','only','then','than','too','very',
    'some','these','those','there','here','where','while','does','did','do',
    'been','being','get','got','use','used','using','via','per','etc','i.e',
    'e.g','fig','table','section','chapter','page','ref','see','note'
}

# ── Simple suffix stemmer ────────────────────────────────────────────────────
SUFFIXES = [
    ('ational','ate'),('tional','tion'),('enci','ence'),('anci','ance'),
    ('izing','ize'),('ising','ise'),('isation','ise'),('ization','ize'),
    ('ations','ate'),('nesses','ness'),('ments','ment'),('ities','ity'),
    ('eness','ene'),('ically','ic'),('fulness','ful'),('ously','ous'),
    ('ively','ive'),('ation','ate'),('alism','al'),('ness',''),
    ('ment',''),('ful',''),('ous',''),('ive',''),('ing',''),
    ('ies','y'),('ied','y'),('ers',''),('ed',''),('er',''),('ly',''),('s',''),
]

def stem(word):
    if len(word) <= 4:
        return word
    for suf, rep in SUFFIXES:
        if word.endswith(suf) and len(word) - len(suf) >= 3:
            return word[:-len(suf)] + rep
    return word

def preprocess(text):
    """Return list of (original_word, stemmed) for indexing."""
    words = re.findall(r'[a-zA-Z]{3,}', text.lower())
    result = []
    for w in words:
        if w not in STOP:
            result.append((w, stem(w)))
    return result

# ── Synonyms ────────────────────────────────────────────────────────────────
SYNONYMS_RAW = {
    'secure':      ['safe','protect','private','guard','confidential','security','encryption'],
    'security':    ['safe','protect','private','encryption','secure'],
    'safe':        ['secure','protect','private','guard'],
    'protection':  ['secure','encryption','privacy','safety'],
    'encrypt':     ['secure','cipher','encode','protect'],
    'encryption':  ['secure','cipher','encode','protection','cryptography'],
    'private':     ['confidential','secure','hidden','personal','privacy'],
    'privacy':     ['confidential','secure','private','protection'],
    'search':      ['find','query','lookup','retrieve','seek'],
    'find':        ['search','locate','discover','retrieve'],
    'query':       ['search','find','lookup','request'],
    'delete':      ['remove','erase','drop','eliminate'],
    'remove':      ['delete','erase','eliminate'],
    'insert':      ['add','upload','store','save'],
    'add':         ['insert','upload','store'],
    'cloud':       ['server','remote','online','storage','host'],
    'server':      ['cloud','host','remote','machine'],
    'data':        ['information','records','files','documents','content'],
    'document':    ['file','record','paper','text','data'],
    'file':        ['document','record','data','text'],
    'verify':      ['check','validate','confirm','authenticate','verification'],
    'verification':['check','validate','confirm','integrity','verify'],
    'forward':     ['future','upcoming','insert','new'],
    'backward':    ['previous','past','delete','old'],
    'integrity':   ['validity','correctness','verification','authentication'],
    'key':         ['password','secret','token','credential'],
    'index':       ['indexes','inverted','forward','table','structure'],
    'hash':        ['sha256','digest','hmac','checksum'],
    'scheme':      ['algorithm','protocol','method','approach','system'],
    'efficient':   ['fast','quick','optimized','performance','speed'],
    'dynamic':     ['update','insert','delete','change','modify'],
}

def get_synonyms(original_word):
    w = original_word.lower()
    result = set()
    if w in SYNONYMS_RAW:
        result.update(SYNONYMS_RAW[w])
    for key, vals in SYNONYMS_RAW.items():
        if w in [v.lower() for v in vals]:
            result.add(key)
            result.update(vals)
    result.discard(w)
    return result

# ── Edit distance ────────────────────────────────────────────────────────────
def edit_distance(a, b):
    if abs(len(a) - len(b)) > 2: return 99
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[:], i
        for j in range(1, n + 1):
            dp[j] = prev[j-1] if a[i-1] == b[j-1] else 1 + min(prev[j], dp[j-1], prev[j-1])
    return dp[n]

# ── Crypto helpers ───────────────────────────────────────────────────────────
SECRET_16 = b'\x01' * 16

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def prf(master_key, data):
    """HMAC-SHA256 → (k1 16B, k2 16B)."""
    if isinstance(data, str):
        data = data.encode()
    h = HMAC.new(master_key[:32], data, SHA256)
    raw = h.digest()
    return raw[:16], raw[16:]

def prp(k1, pi):
    return AES.new(k1, AES.MODE_ECB).encrypt(pi)

def aes_enc(k2, plaintext, key_bits=128):
    key = k2[:16] if key_bits == 128 else (k2 + k2)[:32]
    pad = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad] * pad)
    iv = get_random_bytes(16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)
    return iv + ct

def aes_dec(k2, ciphertext, key_bits=128):
    key = k2[:16] if key_bits == 128 else (k2 + k2)[:32]
    iv, ct = ciphertext[:16], ciphertext[16:]
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad = plain[-1]
    return plain[:-pad]

def mac_fn(k2, data):
    return HMAC.new(k2, data, SHA256).digest()[:16]

# ── TF-IDF ───────────────────────────────────────────────────────────────────
def tfidf(term_stem, doc_id, docs_stem_freq, doc_count):
    tf = docs_stem_freq.get(doc_id, {}).get(term_stem, 0)
    df = sum(1 for d in docs_stem_freq.values() if term_stem in d)
    if tf == 0 or df == 0: return 0.0
    return round(tf * math.log((doc_count + 1) / (df + 1)), 4)

# ── SSE Engine ───────────────────────────────────────────────────────────────
class SSEEngine:
    def __init__(self):
        self.reset()

    def reset(self):
        self.master_key  = None
        self.key_bits    = 128
        self.DI          = {}     # stem → (π, h)
        self.EIinx       = {}     # cw_hex → (ca_hex, cid_hex)
        self.doc_text    = {}     # doc_id → raw text
        self.doc_name    = {}     # doc_id → filename
        self.doc_stems   = {}     # doc_id → {stem: freq}
        self.doc_words   = {}     # doc_id → [(original, stem)]
        self.vocab       = set()
        self.orig_vocab  = set()
        self.deleted_ids = set()  # track which doc_ids have been deleted
        self.op_log      = []
        self._doc_ctr    = 0

    # ── Setup ──────────────────────────────────────────────────────────────
    def setup(self, sensitivity='normal'):
        self.key_bits   = 256 if sensitivity == 'sensitive' else 128
        key_bytes       = self.key_bits // 8
        self.master_key = get_random_bytes(key_bytes)
        self.DI = {}; self.EIinx = {}
        self.doc_text = {}; self.doc_name = {}
        self.doc_stems = {}; self.doc_words = {}
        self.vocab = set(); self.orig_vocab = set()
        self.deleted_ids = set(); self.op_log = []
        self._doc_ctr = 0
        self._log('SETUP', f'AES-{self.key_bits} initialized · key={self.master_key.hex()[:16]}…')
        return {
            'status':    'success',
            'key_bits':  self.key_bits,
            'algorithm': f'AES-{self.key_bits}',
            'key_hex':   self.master_key.hex()
        }

    # ── Ingest ─────────────────────────────────────────────────────────────
    def ingest(self, text, filename='document.txt'):
        if not self.master_key:
            return {'status': 'error', 'message': 'Call setup first'}

        self._doc_ctr += 1
        doc_id = f'doc{self._doc_ctr:03d}'
        self.doc_text[doc_id]  = text
        self.doc_name[doc_id]  = filename

        pairs = preprocess(text)
        self.doc_words[doc_id] = pairs

        freq = defaultdict(int)
        for _, s in pairs:
            freq[s] += 1
        self.doc_stems[doc_id] = dict(freq)
        self.vocab.update(freq.keys())
        self.orig_vocab.update(orig for orig, _ in pairs)

        n = len(self.doc_stems)
        for stem_w, f in freq.items():
            score = tfidf(stem_w, doc_id, self.doc_stems, n)
            self._update_index(stem_w, doc_id, op=0, score=score)

        top = sorted(freq.items(), key=lambda x: -x[1])[:8]
        self._log('INSERT', f'{filename} → {doc_id} · {len(freq)} unique stems · op=0 (insert)')
        return {
            'status':       'success',
            'doc_id':       doc_id,
            'filename':     filename,
            'unique_stems': len(freq),
            'total_tokens': len(pairs),
            'top_keywords': [{'word': w, 'freq': f} for w, f in top],
        }

    # ── DELETE — Backward Privacy ──────────────────────────────────────────
    def delete(self, doc_id):
        """
        Backward privacy implementation.
        For every stem indexed for doc_id, insert a delete-flag entry (op=1)
        into the same Jianding chain. The server stores this identically to
        an insert — it cannot distinguish op=0 from op=1 because the flag is
        inside the AES ciphertext. During future searches the client decrypts
        the chain and subtracts any doc_id with op=1 from the result set S,
        so the deleted document never appears in search results.
        """
        if not self.master_key:
            return {'status': 'error', 'message': 'Call setup first'}
        if doc_id not in self.doc_text:
            return {'status': 'error', 'message': f'{doc_id} not found or already deleted'}

        stems_freq = self.doc_stems.get(doc_id, {})
        if not stems_freq:
            return {'status': 'error', 'message': f'No index entries for {doc_id}'}

        n = len(self.doc_stems)
        count = 0
        for stem_w, freq in stems_freq.items():
            score = tfidf(stem_w, doc_id, self.doc_stems, n)
            # op=1 → delete flag; server cannot distinguish from op=0
            self._update_index(stem_w, doc_id, op=1, score=score)
            count += 1

        # Remove from local client state (backward privacy —
        # the doc_id will be subtracted from results during decryption)
        filename = self.doc_name.get(doc_id, doc_id)
        self.doc_text.pop(doc_id, None)
        self.doc_name.pop(doc_id, None)
        self.doc_stems.pop(doc_id, None)
        self.doc_words.pop(doc_id, None)
        self.deleted_ids.add(doc_id)

        self._log(
            'DELETE',
            f'{doc_id} ({filename}) → {count} delete-flag entries (op=1) added to chain · backward privacy enforced'
        )
        return {
            'status':          'success',
            'doc_id':          doc_id,
            'filename':        filename,
            'entries_flagged': count,
            'message': (
                f'Backward privacy: {count} op=1 delete entries inserted into index chain. '
                f'Future searches will subtract {doc_id} from result set S during decryption.'
            )
        }

    # ── Internal Jianding update ───────────────────────────────────────────
    def _update_index(self, stem_w, doc_id, op, score=0.0):
        """
        Hexie update with Jianding chained MAC.
        op=0 → insert (forward privacy via fresh random r each call)
        op=1 → delete (backward privacy — server sees identical structure)
        """
        k1, k2 = prf(self.master_key, stem_w)

        if stem_w in self.DI:
            pi, h_prev = self.DI[stem_w]
        else:
            pi, h_prev = SECRET_16, SECRET_16

        # plaintext: op(1) + doc_id(12) + score(4) + prev_mac(16) = 33 bytes
        score_bytes = struct.pack('>f', float(score))
        plaintext   = (bytes([op])
                       + doc_id.encode()[:12].ljust(12, b'\x00')
                       + score_bytes
                       + h_prev)

        cid    = aes_enc(k2, plaintext, self.key_bits)
        r      = get_random_bytes(16)        # fresh blinding string each call
        pi_new = xor_bytes(pi, r)            # π_new = π ⊕ r  (forward privacy)
        cw     = hashlib.sha256(pi_new).digest()
        ca     = xor_bytes(r, prp(k1, pi_new))  # c_a = r ⊕ PRP(k1, π_new)
        new_h  = mac_fn(k2, cid)            # Jianding MAC

        self.DI[stem_w]       = (pi_new, new_h)
        self.EIinx[cw.hex()]  = (ca.hex(), cid.hex())

    # ── Chain traversal + Jianding MAC verification ────────────────────────
    def _traverse(self, stem_w):
        if stem_w not in self.DI:
            return [], False

        k1, k2       = prf(self.master_key, stem_w)
        pi, stored_h = self.DI[stem_w]

        enc_list = []
        c_bar    = hashlib.sha256(pi).digest()
        while c_bar.hex() in self.EIinx:
            ca_hex, cid_hex = self.EIinx[c_bar.hex()]
            ca  = bytes.fromhex(ca_hex)
            cid = bytes.fromhex(cid_hex)
            r   = xor_bytes(ca, prp(k1, pi))
            pi  = xor_bytes(pi, r)
            enc_list.append((cid, k2))
            if pi == SECRET_16: break
            c_bar = hashlib.sha256(pi).digest()

        # Jianding — verify MAC chain backward
        verified = True
        h_check  = stored_h
        for cid, k2_v in reversed(enc_list):
            computed = mac_fn(k2_v, cid)
            if computed != h_check:
                verified = False
                break
            try:
                plain   = aes_dec(k2_v, cid, self.key_bits)
                h_check = plain[17:33]
            except Exception:
                verified = False
                break

        # Decode — op=1 entries subtract from result set (backward privacy)
        decoded = []
        if verified:
            result_set = {}   # doc_id → score (apply op in order)
            for cid, k2_v in enc_list:
                try:
                    plain  = aes_dec(k2_v, cid, self.key_bits)
                    op     = plain[0]
                    doc_id = plain[1:13].rstrip(b'\x00').decode(errors='ignore')
                    score  = struct.unpack('>f', plain[13:17])[0]
                    if not doc_id:
                        continue
                    if op == 1:
                        result_set.pop(doc_id, None)   # backward privacy: remove
                    else:
                        result_set[doc_id] = round(score, 4)  # insert
                except Exception:
                    pass
            decoded = [{'doc_id': k, 'op': 0, 'score': v} for k, v in result_set.items()]

        return decoded, verified

    # ── Smart search — auto fallback ───────────────────────────────────────
    def smart_search(self, query):
        t0    = time.perf_counter()
        query = query.strip()

        multi_and   = re.split(r'\bAND\b', query, flags=re.I)
        multi_or    = re.split(r'\bOR\b',  query, flags=re.I)
        multi_comma = [x.strip() for x in query.split(',') if x.strip()]

        if len(multi_and) > 1:
            results, verified = self._multi([x.strip() for x in multi_and], 'AND')
            mode = 'multi-AND'
        elif len(multi_or) > 1:
            results, verified = self._multi([x.strip() for x in multi_or], 'OR')
            mode = 'multi-OR'
        elif len(multi_comma) > 1:
            results, verified = self._multi(multi_comma, 'OR')
            mode = 'multi-comma'
        else:
            results, verified, mode = self._single_smart(query)

        for r in results:
            r['snippet']  = self._snippet(r['doc_id'], r.get('matched_word', query))
            r['filename'] = self.doc_name.get(r['doc_id'], r['doc_id'])

        elapsed = round((time.perf_counter() - t0) * 1000, 3)
        self._log('SEARCH',
            f'"{query}" [{mode}] → {len(results)} docs · {elapsed}ms · {"✓ verified" if verified else "⚠ unverified"}'
        )
        return {
            'status':   'success',
            'query':    query,
            'mode':     mode,
            'results':  results,
            'verified': verified,
            'time_ms':  elapsed
        }

    def _single_smart(self, query):
        raw_words = re.findall(r'[a-zA-Z]{3,}', query.lower())
        words = [(w, stem(w)) for w in raw_words if w not in STOP]
        if not words:
            return [], True, 'no-terms'

        # 1. Exact
        results, verified = self._search_stems([s for _, s in words], label=query)
        if results:
            for r in results: r['matched_word'] = query
            return results, verified, 'exact'

        # 2. Fuzzy
        fuzzy_stems = set()
        fuzzy_found = []
        for orig, s in words:
            for v_orig in self.orig_vocab:
                max_dist = 2 if len(orig) > 7 else 1
                if 0 < edit_distance(orig, v_orig) <= max_dist:
                    fuzzy_stems.add(stem(v_orig))
                    fuzzy_found.append(v_orig)
            for v_stem in self.vocab:
                max_dist = 2 if len(s) > 6 else 1
                if 0 < edit_distance(s, v_stem) <= max_dist:
                    fuzzy_stems.add(v_stem)
        if fuzzy_stems:
            results, verified = self._search_stems(list(fuzzy_stems), label=query)
            if results:
                for r in results: r['matched_word'] = query
                return results, verified, f'fuzzy ({", ".join(set(fuzzy_found[:3]))})'

        # 3. Semantic
        syn_stems = set()
        syn_found = []
        for orig, s in words:
            for syn in get_synonyms(orig):
                syn_stem = stem(syn)
                if syn_stem in self.vocab:
                    syn_stems.add(syn_stem)
                    syn_found.append(syn)
                if syn in self.orig_vocab:
                    syn_stems.add(stem(syn))
                    syn_found.append(syn)
        if syn_stems:
            results, verified = self._search_stems(list(syn_stems), label=query)
            if results:
                for r in results: r['matched_word'] = query
                return results, verified, f'semantic ({", ".join(set(syn_found[:3]))})'

        return [], True, 'no-match'

    def _search_stems(self, stems, label=''):
        docs = {}
        verified = True
        for s in stems:
            decoded, ver = self._traverse(s)
            if not ver: verified = False
            for d in decoded:
                did = d['doc_id']
                # op=1 entries are already resolved inside _traverse
                # only op=0 survivors reach here
                docs[did] = max(docs.get(did, 0), d['score'])
        ranked = [{'doc_id': k, 'score': v} for k, v in docs.items()]
        ranked.sort(key=lambda x: -x['score'])
        for i, r in enumerate(ranked): r['rank'] = i + 1
        return ranked, verified

    def _multi(self, terms, mode='AND'):
        sets = []
        verified = True
        for term in terms:
            res, ver, _ = self._single_smart(term)
            if not ver: verified = False
            sets.append({r['doc_id']: r['score'] for r in res})
        if not sets:
            return [], verified
        if mode == 'AND':
            common = set(sets[0].keys())
            for s in sets[1:]: common &= s.keys()
            docs = {d: sum(s.get(d, 0) for s in sets) for d in common}
        else:
            docs = {}
            for s in sets:
                for d, sc in s.items():
                    docs[d] = docs.get(d, 0) + sc
        ranked = [{'doc_id': k, 'score': v} for k, v in docs.items()]
        ranked.sort(key=lambda x: -x['score'])
        for i, r in enumerate(ranked): r['rank'] = i + 1
        return ranked, verified

    def _snippet(self, doc_id, query, window=40):
        text = self.doc_text.get(doc_id, '')
        if not text:
            return ''
        words = re.findall(r'[a-zA-Z]{3,}', query.lower())
        best_pos = -1
        for w in words:
            m = re.search(re.escape(w), text.lower())
            if m:
                best_pos = m.start(); break
            sw = stem(w)
            for orig, st in self.doc_words.get(doc_id, []):
                if st == sw:
                    idx = text.lower().find(orig)
                    if idx != -1:
                        best_pos = idx; break
            if best_pos != -1: break
        if best_pos == -1:
            return text[:150].strip() + '…'
        start   = max(0, best_pos - window)
        end     = min(len(text), best_pos + window + len(words[0]) if words else best_pos + window)
        snippet = text[start:end].strip()
        if start > 0:        snippet = '…' + snippet
        if end < len(text):  snippet += '…'
        return snippet

    def stats(self):
        return {
            'documents':        len(self.doc_text),
            'deleted_docs':     len(self.deleted_ids),
            'index_entries':    len(self.EIinx),
            'vocab_size':       len(self.vocab),
            'keywords_tracked': len(self.DI),
            'operations':       len(self.op_log),
            'algorithm':        f'AES-{self.key_bits}' if self.master_key else 'Not initialized',
            'initialized':      self.master_key is not None,
            'log':              self.op_log[-30:]
        }

    def _log(self, kind, msg):
        self.op_log.append({'kind': kind, 'msg': msg, 'ts': time.strftime('%H:%M:%S')})


engine = SSEEngine()
