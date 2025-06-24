from __future__ import annotations
import platform
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
import hashlib, hmac, os, sys, time, itertools, string, logging, zlib, threading, concurrent.futures as cf, tkinter as tk, multiprocessing as mp
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple, Dict
import subprocess

def _pip_install(pkg: str) -> None:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])
    except Exception:
        pass

try:
    from argon2 import PasswordHasher, Type
except ImportError:
    _pip_install("argon2-cffi")
    from argon2 import PasswordHasher, Type

try:
    from passlib.hash import nthash
except ImportError:
    _pip_install("passlib")
    from passlib.hash import nthash

_HAS_FAST_HASHES = False
try:
    from Crypto.Hash import MD4 as _MD4, RIPEMD160 as _RIPEMD160
    _HAS_FAST_HASHES = True
except ImportError:
    _pip_install("pycryptodome")
    try:
        from Crypto.Hash import MD4 as _MD4, RIPEMD160 as _RIPEMD160
        _HAS_FAST_HASHES = True
    except ImportError:
        _HAS_FAST_HASHES = False

try:
    import bcrypt
except ImportError:
    _pip_install("bcrypt")
    try:
        import bcrypt
    except ImportError:
        bcrypt = None

try:
    import psutil
except ImportError:
    _pip_install("psutil")
    try:
        import psutil
    except ImportError:
        psutil = None

try:
    import chardet
except ImportError:
    _pip_install("chardet")
    try:
        import chardet
    except ImportError:
        chardet = None

CPU_USAGE_THRESHOLD = 99.5
_CPU_CHECK_INTERVAL = 0.2
_SCRIPT_DIR = (Path(sys.executable).parent if getattr(sys, "frozen", False)
               else Path(__file__).resolve().parent)
LOG_FILE = str(_SCRIPT_DIR / "Hash_Cracking_Results_ClatsCracker.txt")
ALIAS_MAP = {'shakeke128': 'shake128', 'sha1v2': 'sha1_v2', 'ntplm': 'ntlm', 'md5-sha1': 'md5_sha1'}
_DEFAULT_THREADS = max(1, (os.cpu_count() or 1))
_ENC_CACHE: Dict[str, str] = {}
SCRIPT_NAME = Path(sys.argv[0]).name if sys.argv else ''
logger = logging.getLogger("clatscracker")
logger.setLevel(logging.INFO)
_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(filename)s — %(message)s"))
logger.addHandler(_fh)
write_log = logger.info

hash_lengths = {'crc32': 8,'adler32': 8,'md4': 32,'md5': 32,'ripemd160': 40,'sha1': 40,'sha1_v2': 40,'sha224': 56,'sha256': 64,'sha3_224': 56,'sha3_256': 64,'sha3_384': 96,'sha3_512': 128,'sha512': 128,'sha512_224': 56,'sha512_256': 64,'blake2_224': 56,'blake2b': 128,'blake2s': 64,'sha384': 96,'shake128': 64,'shake256': 128,'shakeke128': 64,'sm3': 64,'md5_sha1': 72,'mdc2': 32,'whirlpool': 128,'scrypt': 128}
_HASH_FUNCS = {
    'crc32': lambda b: format(zlib.crc32(b) & 0xffffffff, '08x'),
    'adler32': lambda b: format(zlib.adler32(b) & 0xffffffff, '08x'),
    'md4': (lambda b: _MD4.new(data=b).hexdigest()) if _HAS_FAST_HASHES else (lambda b: hashlib.new('md4', b).hexdigest()),
    'md5': lambda b: hashlib.md5(b).hexdigest(),
    'ripemd160': (lambda b: _RIPEMD160.new(data=b).hexdigest()) if _HAS_FAST_HASHES else (lambda b: hashlib.new('ripemd160', b).hexdigest()),
    'blake2_224': lambda b: hashlib.blake2b(b, digest_size=28).hexdigest(),
    'sha224': lambda b: hashlib.sha224(b).hexdigest(),'sha256': lambda b: hashlib.sha256(b).hexdigest(),'sha512': lambda b: hashlib.sha512(b).hexdigest(),
    'sha3_224': lambda b: hashlib.sha3_224(b).hexdigest(),'sha3_256': lambda b: hashlib.sha3_256(b).hexdigest(),'sha3_384': lambda b: hashlib.sha3_384(b).hexdigest(),'sha3_512': lambda b: hashlib.sha3_512(b).hexdigest(),
    'sha1': lambda b: hashlib.sha1(b).hexdigest(),'sha512_224': lambda b: hashlib.new('sha512_224', b).hexdigest(),'sha512_256': lambda b: hashlib.new('sha512_256', b).hexdigest(),
    'blake2b': lambda b: hashlib.blake2b(b).hexdigest(),'blake2s': lambda b: hashlib.blake2s(b).hexdigest(),'sha384': lambda b: hashlib.sha384(b).hexdigest(),
    'shake128': lambda b: hashlib.shake_128(b).hexdigest(32),'shake256': lambda b: hashlib.shake_256(b).hexdigest(64),'shakeke128': lambda b: hashlib.shake_128(b).hexdigest(32),
    'sm3': lambda b: hashlib.new('sm3', b).hexdigest(),
    'md5_sha1': lambda b: hashlib.md5(b).hexdigest() + hashlib.sha1(b).hexdigest(),
    'mdc2': lambda b: hashlib.new('mdc2', b).hexdigest(),'whirlpool': lambda b: hashlib.new('whirlpool', b).hexdigest(),
    'scrypt': lambda b: hashlib.scrypt(b, salt=b'', n=16384, r=8, p=1, dklen=64).hex(),
}
_ARGON2_PH = PasswordHasher(type=Type.ID)

def canonical_algo(name: str) -> str:
    return ALIAS_MAP.get(name.lower(), name.lower())

class CrackerState:
    def __init__(self):
        self.passwords_tried = 0
        self.total_passwords = 0
        self.found_password: Optional[str] = None
        self.threads_count = _DEFAULT_THREADS
        self.start_time: Optional[float] = None
        self.abort_requested = False
        self.cracking_complete = False
        self.progress_lock = threading.Lock()
        self.found_lock = threading.Lock()

def phpass_verify(password: str, phpass_hash: str) -> bool:
    it = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    if not (phpass_hash.startswith('$P$') or phpass_hash.startswith('$H$')) or len(phpass_hash) != 34:
        return False
    cl = it.index(phpass_hash[3])
    cnt = 1 << cl
    salt = phpass_hash[4:12]
    h = hashlib.md5((salt + password).encode()).digest()
    for _ in range(cnt):
        h = hashlib.md5(h + password.encode()).digest()
    def e(inp: bytes):
        out, val, bits = [], 0, 0
        for byte in inp:
            val |= byte << bits
            bits += 8
            while bits >= 6:
                out.append(it[val & 0x3f])
                val >>= 6
                bits -= 6
        if bits:
            out.append(it[val & 0x3f])
        return ''.join(out)
    return phpass_hash[:12] + e(h)[:22] == phpass_hash

def guess_hash_algorithm(h: str) -> Optional[List[str]]:
    if h.startswith('$2'):
        return ['bcrypt']
    if h.startswith('$argon2id$'):
        return ['argon2id']
    if (h.startswith('$P$') or h.startswith('$H$')) and len(h) == 34:
        return ['phpass_md5']
    hl, l = h.lower(), len(h)
    if l == 32 and all(c in '0123456789abcdef' for c in hl):
        return ['md5', 'ntlm']
    cand = [k for k, v in hash_lengths.items() if l == v]
    if l == 128 and all(c in '0123456789abcdef' for c in hl):
        cand.append('scrypt')
    return list(dict.fromkeys(cand)) or None

def validate_hash_length(a: str, h: str) -> bool:
    if a in {'bcrypt', 'argon2id', 'scrypt', 'phpass_md5', 'ntlm'}:
        return True
    exp = hash_lengths.get(a)
    return False if exp and len(h) != exp else True

_cpu_last = 0.0
_next_cpu_check = 0.0
def throttle_cpu():
    global _cpu_last, _next_cpu_check
    if psutil:
        now = time.time()
        if now >= _next_cpu_check:
            _cpu_last = psutil.cpu_percent(0.05)
            _next_cpu_check = now + _CPU_CHECK_INTERVAL
    if _cpu_last > CPU_USAGE_THRESHOLD:
        time.sleep(0.2)

def compile_checker(d: str, a: str):
    if a == 'bcrypt':
        ref = d.encode()
        return (lambda p: bcrypt and bcrypt.checkpw(p.encode(), ref))
    if a == 'argon2id':
        def _chk(p: str):
            try:
                _ARGON2_PH.verify(d, p)
                return True
            except Exception:
                return False
        return _chk
    if a == 'phpass_md5':
        return lambda p: phpass_verify(p, d)
    if a == 'ntlm':
        return lambda p: nthash.verify(p, d)
    if a == 'sha1_v2':
        return lambda p: hmac.compare_digest(hashlib.sha1(hashlib.sha1(p.encode()).digest()).hexdigest(), d)
    if a == 'scrypt':
        return lambda p: hmac.compare_digest(hashlib.scrypt(p.encode(), salt=b'', n=16384, r=8, p=1, dklen=64).hex(), d)
    if a in ('shake128', 'shakeke128'):
        return lambda p: hmac.compare_digest(hashlib.shake_128(p.encode()).hexdigest(32), d)
    if a == 'shake256':
        return lambda p: hmac.compare_digest(hashlib.shake_256(p.encode()).hexdigest(64), d)
    fn = _HASH_FUNCS.get(a)
    return (lambda p: fn(p.encode()) == d) if fn else (lambda _: False)

def _process_chunk(chunk: List[str], checker, step: int) -> Tuple[int, Optional[str]]:
    processed = 0
    for pwd in chunk:
        processed += 1
        if checker(pwd):
            return processed, pwd
        if processed % step == 0:
            throttle_cpu()
    return processed, None

def detect_file_encoding(path: str, sample: int = 10000) -> str:
    if chardet is None:
        return 'utf-8'
    try:
        with open(path, 'rb') as f:
            return chardet.detect(f.read(sample)).get('encoding') or 'utf-8'
    except Exception:
        return 'utf-8'

def get_line_count(path: str) -> int:
    try:
        enc = _ENC_CACHE.get(path) or detect_file_encoding(path)
        _ENC_CACHE[path] = enc
        with open(path, 'r', encoding=enc, errors='replace') as f:
            return sum(1 for _ in f)
    except Exception:
        return 0

def lines_in_chunks(path: str, chunk: int = 300_000):
    try:
        enc = _ENC_CACHE.get(path) or detect_file_encoding(path)
        _ENC_CACHE[path] = enc
        with open(path, 'r', encoding=enc, errors='replace', buffering=1024 * 1024) as f:
            while True:
                batch = list(itertools.islice(f, chunk))
                if not batch:
                    break
                yield [line.rstrip('\n') for line in batch]
    except Exception:
        return

def _generate_passwords(chars: str, length: int, chunk: int = 100000):
    prod = itertools.product(chars, repeat=length)
    while True:
        slice_ = list(itertools.islice(prod, chunk))
        if not slice_:
            break
        yield [''.join(t) for t in slice_]

def dictionary_crack_worker(path: str, d: str, checker, state: CrackerState, step: int, cb):
    if not os.path.exists(path):
        write_log(f"Dictionary {path} not found")
        return
    for chunk in lines_in_chunks(path):
        if state.abort_requested or state.found_password:
            break
        processed_chunk = 0
        for pwd in chunk:
            if state.abort_requested or state.found_password:
                break
            processed_chunk += 1
            if checker(pwd):
                with state.found_lock:
                    state.found_password = pwd
                    state.abort_requested = True
                    break
        with state.progress_lock:
            state.passwords_tried += processed_chunk
            pct = (state.passwords_tried / state.total_passwords * 100) if state.total_passwords else 0
        cb(pct, state)
        if state.abort_requested or state.found_password:
            break

def concurrent_hash_cracker(dicts: List[str], d: str, a: str, state: CrackerState, cb, done):
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    state.cracking_complete = False
    write_log("Dictionary cracking started")
    state.start_time = time.time()
    state.total_passwords = sum(get_line_count(p) for p in dicts if os.path.exists(p))
    if not state.total_passwords:
        write_log("Empty dictionaries")
        done(None)
        return
    checker = compile_checker(d, a)
    max_workers = min(state.threads_count, len(dicts))
    with ThreadPoolExecutor(max_workers=max_workers) as tpe:
        futs = [tpe.submit(dictionary_crack_worker, p, d, checker, state, 5_000_000, cb) for p in dicts if os.path.exists(p)]
        while True:
            if state.found_password:
                state.abort_requested = True
                for f in futs:
                    f.cancel()
                break
            if all(f.done() for f in futs):
                break
            time.sleep(0.05)
    write_log("Dictionary cracking complete")
    done(state.found_password)

def brute_force_crack(d: str, a: str, chars: str, length: int, state: CrackerState, cb, done):
    state.found_password = None
    state.passwords_tried = 0
    state.abort_requested = False
    state.cracking_complete = False
    state.start_time = time.time()
    state.total_passwords = len(chars) ** length
    write_log("Bruteforce started")
    checker = compile_checker(d, a)
    step = max(1, 5_000_000 // state.threads_count)
    for batch in _generate_passwords(chars, length, step):
        if state.abort_requested or state.found_password:
            break
        futs = [_POOL.submit(_process_chunk, batch[i:i + step], checker, step) for i in range(0, len(batch), step)]
        for fut in cf.as_completed(futs):
            if state.abort_requested:
                break
            try:
                proc, found = fut.result()
            except Exception:
                continue
            with state.progress_lock:
                state.passwords_tried += proc
                pct = (state.passwords_tried / state.total_passwords * 100) if state.total_passwords else 0
            cb(pct, state)
            if found:
                with state.found_lock:
                    state.found_password = found
                    state.abort_requested = True
                    break
        if state.found_password or state.abort_requested:
            break
    write_log("Bruteforce complete")
    done(state.found_password)

class HashCrackerGUI:
    ...
    # (GUI class is **identical**; omitted here for brevity — no platform changes required)
    ...

def _worker_init(nice_val: int):
    try:
        os.nice(nice_val)
    except AttributeError:
        pass

def main():
    mp.freeze_support()
    try:
        mp.set_start_method("spawn", force=True)
    except RuntimeError:
        pass
    global _POOL
    _POOL = ThreadPoolExecutor(max_workers=os.cpu_count() or 1)
    root = tk.Tk()
    HashCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()