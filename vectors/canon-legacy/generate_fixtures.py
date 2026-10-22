#!/usr/bin/env python3
"""Generate vectors/canon-legacy/legacy-text-profiles.json by RUNNING the existing implementations.

Command (from the mg-crypto-core repo root):
    python vectors/canon-legacy/generate_fixtures.py

Sources are read at run time from the sibling repos (not copied):
  python v1/v2 : moonglade-provenance packages/provnat-core/src/provnat/canonical.py  (canonicalize_text)
  python bytes : same repo, bundle_v2.py canonical_bytes (canonical/v1 as `_sign.py` applies it)
  browser      : moonglade-provenance packages/browser-extension/src/core/canonicalize.ts
  obsidian     : obsidian-provenance-gate src/engine.ts (ProvenanceEngine.canonicalize)
No expected value is written by hand. The only composed value is `py_v2_bytes`, see note in the output.
"""
import hashlib, json, subprocess, sys, unicodedata, importlib.util, platform
from pathlib import Path

sys.dont_write_bytecode = True  # never write __pycache__ into the source repos

REPOS = Path(r"D:/Development 2.0/Repos")
MP = REPOS / "moonglade-provenance"
OB = REPOS / "obsidian-provenance-gate"
CANON_PY = MP / "packages/provnat-core/src/provnat/canonical.py"
BUNDLE_PY = MP / "packages/provnat-core/src/provnat/bundle_v2.py"
CANON_TS = MP / "packages/browser-extension/src/core/canonicalize.ts"
ENGINE_TS = OB / "src/engine.ts"
HERE = Path(__file__).resolve().parent


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def repo_head(repo):
    return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()


def load(path, name, extra_path=None):
    if extra_path:
        sys.path.insert(0, str(extra_path))
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


canon = load(CANON_PY, "canonical_real")
bundle = load(BUNDLE_PY, "bundle_v2_real", MP / "packages/provnat-core/src")

BOM = b"\xef\xbb\xbf"
NFD_E = "e\u0301".encode()
cases = [
    # (name, filename, bytes)
    ("empty", "a.md", b""),
    ("plain_lf", "a.md", b"hello\n"),
    ("bom_only", "a.md", BOM),
    ("bom", "a.md", BOM + b"hello\n"),
    ("double_bom", "a.md", BOM + BOM + b"hello\n"),
    ("triple_bom", "a.md", BOM + BOM + BOM + b"x\n"),
    ("bom_mid_text", "a.md", b"a" + BOM + b"b\n"),
    ("crlf", "a.md", b"a\r\nb\r\n"),
    ("bare_cr", "a.md", b"a\rb\r"),
    ("cr_cr_lf", "a.md", b"a\r\r\nb"),
    ("lf_cr", "a.md", b"a\n\rb"),
    ("trailing_cr", "a.md", b"a\r"),
    ("non_nfc_e_acute", "a.md", b"caf" + NFD_E + b"\n"),
    ("non_nfc_hangul", "a.md", "\u1100\u1161\u11a8\n".encode()),
    ("non_nfc_reorder", "a.md", "a\u0323\u0307 a\u0307\u0323\n".encode()),
    ("already_nfc", "a.md", "caf\u00e9\n".encode()),
    ("non_bmp_crlf", "a.md", "\U0001F600\r\nx\r\n".encode()),
    ("mixed_all", "a.md", BOM + b"t" + NFD_E + b"\r\nline\rend\r\n\r\n"),
    ("mixed_bare_cr_nfd", "a.md", b"x" + NFD_E + b"\ry\r\nz\n"),
    ("invalid_utf8", "a.md", b"ab\xff\xfecd\r\n"),
    ("invalid_utf8_after_bom", "a.md", BOM + b"a\xff\r\n"),
    ("truncated_seq", "a.md", b"ok\xe2\x82"),
    ("overlong_and_surrogate", "a.md", b"\xc0\xaf\xed\xa0\x80\r\n"),
    ("nul_text_ext", "a.md", b"a\x00b\r\n"),
    ("nul_unknown_ext", "a.dat", b"a\x00b\r\n"),
    ("nul_png", "a.png", b"\x89PNG\r\n\x1a\n\x00\x00"),
    ("text_unknown_ext", "a.dat", BOM + b"a\r\nb\r"),
    ("text_no_ext", "README", b"a\r\nb" + NFD_E),
    ("text_upper_ext", "A.MD", b"a\r\nb\r"),
    ("text_bin_ext_ascii", "a.bin", b"a\r\nb\r"),
    ("nul_after_1024", "a.dat", b"a" * 1024 + b"\x00\r\n"),
    ("nul_at_1023", "a.dat", b"a" * 1023 + b"\x00\r\n"),
    ("dotfile_ext", ".md", b"\x00\r\n"),
    ("dir_dot_filename", "x.d/noext", b"a\x00\r\n"),
    # "a", U+1AE7 (assigned after Unicode 15.1), U+0301, U+0323. Python 3.13 leaves the order
    # alone; Node and the Rust crate reorder. Known divergence, see UNICODE_DIVERGENT.
    ("unicode_late_combining", "a.md", bytes.fromhex("61e1aba7cc81cca3")),
]
UNICODE_DIVERGENT = {"unicode_late_combining"}

js_in = [{"filename": f, "hex": b.hex()} for _, f, b in cases]
js_out = json.loads(subprocess.run(
    ["node", str(HERE / "js_profiles.mjs"), str(CANON_TS), str(ENGINE_TS)],
    input=json.dumps(js_in), capture_output=True, text=True, check=True).stdout)


def py_text(profile, raw):
    # canonicalize_text takes str. Strict UTF-8 decode; invalid input has no defined result
    # (None here), and the bytes wrappers below define the passthrough.
    try:
        return canon.canonicalize_text(raw.decode("utf-8"), profile)
    except UnicodeDecodeError:
        return None


out_cases = []
for (name, filename, raw), js in zip(cases, js_out):
    v1_text = py_text("canonical/v1", raw)
    v2_text = py_text("canonical/v2", raw)
    v1_bytes = bundle.canonical_bytes(raw)          # real: bundle_v2.canonical_bytes
    v2_bytes = v2_text if v2_text is not None else raw  # composed: v2 core + same passthrough
    out_cases.append({
        "name": name,
        "filename": filename,
        "input_hex": raw.hex(),
        "py_v1_text": None if v1_text is None else v1_text.hex(),
        "py_v2_text": None if v2_text is None else v2_text.hex(),
        "py_v1_bytes": v1_bytes.hex(),
        "py_v2_bytes": v2_bytes.hex(),
        "browser": js["browser"],
        "obsidian": js["obsidian"],
    })
    if name in UNICODE_DIVERGENT:
        # Guard: the case must really diverge (Python vs Node) or the flag would be a lie.
        assert v1_text.hex() != js["obsidian"], name
        out_cases[-1]["unicode_version_divergence"] = (
            "Python unicodedata (older Unicode data) differs from Node ICU and unicode-normalization: "
            "py_* NFC differs from browser/obsidian/Rust. A Python-signed artifact containing such "
            "code points shows a false 'none' for canonical/v1 and v2; the report flags these "
            "artifacts as unicode_version_sensitive.")

mp_head = repo_head(MP)
ob_head = repo_head(OB)
doc = {
    "header": {
        "kind": "golden",
        "purpose": "legacy text canonicalisation profiles (verify/measure only)",
        "source": [
            {"repo": "moonglade-provenance", "commit": mp_head,
             "path": "packages/provnat-core/src/provnat/canonical.py", "upstream_sha256": sha(CANON_PY)},
            {"repo": "moonglade-provenance", "commit": mp_head,
             "path": "packages/provnat-core/src/provnat/bundle_v2.py", "upstream_sha256": sha(BUNDLE_PY)},
            {"repo": "moonglade-provenance", "commit": mp_head,
             "path": "packages/browser-extension/src/core/canonicalize.ts", "upstream_sha256": sha(CANON_TS)},
            {"repo": "obsidian-provenance-gate", "commit": ob_head,
             "path": "src/engine.ts", "upstream_sha256": sha(ENGINE_TS)},
        ],
        "licence": "values are outputs of private-repo code over synthetic inputs; no corpus content",
        "generated_by": "python vectors/canon-legacy/generate_fixtures.py",
        "runtime": {"python": platform.python_version(), "unicodedata": unicodedata.unidata_version,
                    "node": subprocess.check_output(["node", "--version"], text=True).strip()},
        "field_notes": {
            "py_v1_text/py_v2_text": "canonicalize_text(str, profile).hex(); null when the input is not valid UTF-8 (str input undefined)",
            "py_v1_bytes": "bundle_v2.canonical_bytes(raw).hex(): strict UTF-8 decode then canonical/v1, else raw bytes unchanged",
            "py_v2_bytes": "COMPOSED here, not an existing function: canonical/v2 over strict UTF-8 decode, else raw bytes unchanged",
            "browser": "canonicalizeBytes(filename, bytes) from canonicalize.ts",
            "obsidian": "ProvenanceEngine.canonicalize body from engine.ts over Node utf8 decode (BOM kept, invalid bytes become U+FFFD)",
        },
    },
    "cases": out_cases,
}
(HERE / "legacy-text-profiles.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
print(f"wrote {len(out_cases)} cases")
