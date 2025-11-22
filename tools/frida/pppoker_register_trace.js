// PPPoker register trace via Frida (Windows)
// Captures plaintext HTTP for /poker/api/register.php by hooking WinHTTP/WinINet and SChannel EncryptMessage.
// Prints full request and parsed query params (username/password/t/imei/clientvar/...)

function wstr(ptr) {
  try { return ptr.isNull() ? "" : ptr.readUtf16String(); } catch (_) { return ""; }
}

function bytesToAscii(buf) {
  const u8 = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u8.length; i++) {
    const c = u8[i];
    s += (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : '\u0000';
  }
  return s.replace(/\u0000+/g, '');
}

function parseRequestAndQuery(text) {
  const out = { method: '', path: '', query: '', params: {} };
  try {
    const firstLineIdx = text.indexOf('\r\n');
    const firstLine = firstLineIdx > 0 ? text.substring(0, firstLineIdx) : text;
    // e.g. GET /poker/api/register.php?username=... HTTP/1.1
    const m = firstLine.match(/^(GET|POST)\s+([^\s]+)\s+HTTP\//i);
    if (m) {
      out.method = m[1];
      out.path = m[2];
      const qIdx = out.path.indexOf('?');
      if (qIdx !== -1) {
        out.query = out.path.substring(qIdx + 1);
      }
    }
    const q = out.query || '';
    q.split('&').forEach(kv => {
      if (!kv) return;
      const eq = kv.indexOf('=');
      const k = eq === -1 ? kv : kv.substring(0, eq);
      const v = eq === -1 ? '' : kv.substring(eq + 1);
      try {
        const dk = decodeURIComponent(k.replace(/\+/g, ' '));
        const dv = decodeURIComponent(v.replace(/\+/g, ' '));
        out.params[dk] = dv;
      } catch (_) {
        out.params[k] = v;
      }
    });
  } catch (_) {}
  return out;
}

function shouldLog(pathOrBody) {
  if (!pathOrBody) return false;
  const s = pathOrBody.toString();
  return s.indexOf('register.php') !== -1 || s.indexOf('/poker/api/register.php') !== -1 || s.indexOf('login.php') !== -1 || s.indexOf('username=') !== -1;
}

const winhttpReqs = new Map();

function resolveExport(name) {
  try {
    let ptr = Module.findExportByName(null, name);
    if (ptr) return ptr;
    const res = new ApiResolver('module');
    let found = null;
    res.enumerateMatches('*!' + name, {
      onMatch: function (m) { if (!found) found = m; },
      onComplete: function () { }
    });
    return found ? found.address : null;
  } catch (_) {
    return null;
  }
}

function hookWinHttp() {
  const OpenReq = resolveExport('WinHttpOpenRequest');
  const SendReq = resolveExport('WinHttpSendRequest');
  if (OpenReq) {
    Interceptor.attach(OpenReq, {
      onEnter(args) {
        this.verb = wstr(args[1]);
        this.path = wstr(args[2]);
      },
      onLeave(rv) {
        try { winhttpReqs.set(rv.toString(), { verb: this.verb, path: this.path }); } catch (_) {}
      }
    });
  }
  if (SendReq) {
    Interceptor.attach(SendReq, {
      onEnter(args) {
        const hReq = args[0].toString();
        const headers = wstr(args[1]);
        const bodyPtr = args[3];
        var bodyLen = 0;
        try { bodyLen = args[4].toInt32(); } catch (_) { try { bodyLen = parseInt(args[4]); } catch (__) { bodyLen = 0; } }
        const info = winhttpReqs.get(hReq) || { verb: '?', path: '?' };
        let body = '';
        if (!bodyPtr.isNull() && bodyLen > 0) {
          const bytes = Memory.readByteArray(bodyPtr, bodyLen);
          body = bytesToAscii(bytes);
        }
        if (shouldLog(info.path) || shouldLog(body)) {
          console.log('\n=== WinHTTP Request ===');
          console.log('Verb: ' + info.verb + '  Path: ' + info.path);
          if (headers) console.log('Headers: ' + headers);
          if (body) console.log('Body: ' + body);
          try {
            const parsed = parseRequestAndQuery('GET ' + info.path + ' HTTP/1.1');
            if (parsed.query) {
              console.log('QueryParams:', JSON.stringify(parsed.params));
            }
          } catch (_) {}
          console.log('=======================\n');
        }
      }
    });
  }
  return !!(OpenReq || SendReq);
}

function hookWinInet() {
  const OpenReqW = resolveExport('HttpOpenRequestW');
  const SendReqW = resolveExport('HttpSendRequestW');
  const inetReqs = new Map();
  if (OpenReqW) {
    Interceptor.attach(OpenReqW, {
      onEnter(args) { this.verb = wstr(args[1]); this.path = wstr(args[2]); },
      onLeave(rv) { inetReqs.set(rv.toString(), { verb: this.verb, path: this.path }); }
    });
  }
  if (SendReqW) {
    Interceptor.attach(SendReqW, {
      onEnter(args) {
        const hReq = args[0].toString();
        const headers = wstr(args[1]);
        const bodyPtr = args[3];
        var bodyLen = 0;
        try { bodyLen = args[4].toInt32(); } catch (_) { try { bodyLen = parseInt(args[4]); } catch (__) { bodyLen = 0; } }
        const info = inetReqs.get(hReq) || { verb: '?', path: '?' };
        let body = '';
        if (!bodyPtr.isNull() && bodyLen > 0) {
          const bytes = Memory.readByteArray(bodyPtr, bodyLen);
          body = bytesToAscii(bytes);
        }
        if (shouldLog(info.path) || shouldLog(body)) {
          console.log('\n=== WinINet Request ===');
          console.log('Verb: ' + info.verb + '  Path: ' + info.path);
          if (headers) console.log('Headers: ' + headers);
          if (body) console.log('Body: ' + body);
          try {
            const parsed = parseRequestAndQuery('GET ' + info.path + ' HTTP/1.1');
            if (parsed.query) {
              console.log('QueryParams:', JSON.stringify(parsed.params));
            }
          } catch (_) {}
          console.log('=======================\n');
        }
      }
    });
  }
  return !!(OpenReqW || SendReqW);
}

function hookSChannel() {
  const enc = resolveExport('EncryptMessage');
  if (!enc) return false;
  Interceptor.attach(enc, {
    onEnter(args) {
      try {
        const pDesc = args[2];
        if (pDesc.isNull()) return;
        const cBuffers = pDesc.add(4).readU32();
        const pBuffers = pDesc.add(8).readPointer();
        const step = 8 + Process.pointerSize;
        let printed = false;
        for (let i = 0; i < cBuffers; i++) {
          const pBuf = pBuffers.add(i * step);
          const cb = pBuf.readU32();
          const type = pBuf.add(4).readU32();
          const pv = pBuf.add(8).readPointer();
          if (type === 1 && cb > 0 && !pv.isNull()) { // SECBUFFER_DATA
            const bytes = Memory.readByteArray(pv, cb);
            const s = bytesToAscii(bytes);
            if (shouldLog(s) && s.indexOf('HTTP/1.1') !== -1 && !printed) {
              printed = true;
              console.log('\n=== Schannel EncryptMessage (plaintext) ===');
              console.log(s);
              const parsed = parseRequestAndQuery(s);
              if (parsed.query) {
                console.log('QueryParams:', JSON.stringify(parsed.params));
                const keys = ['username','password','t','imei','clientvar','appid','os'];
                const sel = {};
                keys.forEach(k => { if (parsed.params[k] !== undefined) sel[k] = parsed.params[k]; });
                console.log('SelectedParams:', JSON.stringify(sel));
              }
              console.log('==========================================\n');
            }
          }
        }
      } catch (_) {}
    }
  });
  return true;
}

(function main() {
  var ok1=false, ok2=false, ok3=false;
  try { ok1 = hookWinHttp(); } catch (e) { console.log('[!] WinHTTP hook error:', e); }
  try { ok2 = hookWinInet(); } catch (e) { console.log('[!] WinINet hook error:', e); }
  try { ok3 = hookSChannel(); } catch (e) { console.log('[!] SChannel hook error:', e); }
  console.log('[*] Hooks ready. WinHTTP:', ok1, ' WinINet:', ok2, ' SChannel:', ok3);
// libcurl hooks (URL + POSTFIELDS)
var curlMap = new Map();
function hookLibcurl() {
  const setopt = resolveExport('curl_easy_setopt');
  const perform = resolveExport('curl_easy_perform');
  if (!setopt && !perform) return false;
  if (setopt) {
    Interceptor.attach(setopt, {
      onEnter(args) {
        try {
          const easy = args[0].toString();
          const opt = args[1].toInt32();
          const val = args[2];
          let rec = curlMap.get(easy); if (!rec) { rec = { url: '', post: '' }; curlMap.set(easy, rec); }
          if (opt === 10002 /*CURLOPT_URL*/) {
            rec.url = val.isNull() ? '' : val.readUtf8String();
          } else if (opt === 10015 /*CURLOPT_POSTFIELDS*/ || opt === 10165 /*COPYPOSTFIELDS*/) {
            rec.post = val.isNull() ? '' : val.readUtf8String();
          } else if (opt === 10036 /*CURLOPT_CUSTOMREQUEST*/) {
            // ignore
          }
        } catch (_) {}
      }
    });
  }
  if (perform) {
    Interceptor.attach(perform, {
      onEnter(args) {
        try {
          const easy = args[0].toString();
          const rec = curlMap.get(easy) || { url: '', post: '' };
          if (shouldLog(rec.url) || shouldLog(rec.post)) {
            console.log('\n=== libcurl easy_perform ===');
            console.log('URL: ' + rec.url);
            if (rec.post) console.log('POSTFIELDS: ' + rec.post);
            const parsed = parseRequestAndQuery('GET ' + rec.url + ' HTTP/1.1');
            if (parsed.query) {
              console.log('QueryParams:', JSON.stringify(parsed.params));
              const keys = ['username','password','t','imei','clientvar','appid','os'];
              const sel = {}; keys.forEach(k => { if (parsed.params[k] !== undefined) sel[k] = parsed.params[k]; });
              console.log('SelectedParams:', JSON.stringify(sel));
            }
            console.log('============================\n');
          }
        } catch (_) {}
      }
    });
  }
  return true;
}

function toLower(s) { try { return (s||'').toLowerCase(); } catch (_) { return ''; } }

function setupModuleLoadHooks() {
  function tryHookFor(modName) {
    const n = toLower(modName);
    if (n.indexOf('winhttp.dll') !== -1) { if (!globalThis.__winhttpHooked) { globalThis.__winhttpHooked = hookWinHttp(); console.log('[*] WinHTTP loaded, hooked:', !!globalThis.__winhttpHooked); } }
    if (n.indexOf('wininet.dll') !== -1) { if (!globalThis.__wininetHooked) { globalThis.__wininetHooked = hookWinInet(); console.log('[*] WinINet loaded, hooked:', !!globalThis.__wininetHooked); } }
    if (n.indexOf('secur32.dll') !== -1 || n.indexOf('schannel.dll') !== -1) { if (!globalThis.__schannelHooked) { globalThis.__schannelHooked = hookSChannel(); console.log('[*] SChannel loaded, hooked:', !!globalThis.__schannelHooked); } }
    if (n.indexOf('libcurl') !== -1 || n.indexOf('curl.dll') !== -1) { if (!globalThis.__curlHooked) { globalThis.__curlHooked = hookLibcurl(); console.log('[*] libcurl loaded, hooked:', !!globalThis.__curlHooked); } }
  }

  // initial sweep
  try { Process.enumerateModulesSync().forEach(m => tryHookFor(m.name)); } catch (_) {}

  // kernel32 LoadLibraryW/A/ExW
  ['LoadLibraryW','LoadLibraryA','LoadLibraryExW'].forEach(fn => {
    const addr = resolveExport(fn);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          let name = '';
          if (fn === 'LoadLibraryA') name = args[0].readCString();
          else name = wstr(args[0]);
          if (name) tryHookFor(name);
        } catch (_) {}
      }
    });
  });

  // ntdll LdrLoadDll (more reliable)
  const ldr = resolveExport('LdrLoadDll');
  if (ldr) {
    Interceptor.attach(ldr, {
      onEnter(args) {
        try {
          const pustr = args[2];
          if (!pustr.isNull()) {
            const len = pustr.readU16();
            const buf = pustr.add(8).readPointer();
            const name = buf.readUtf16String(len/2);
            if (name) tryHookFor(name);
          }
        } catch (_) {}
      }
    });
  }
}

(function main() {
  var ok1=false, ok2=false, ok3=false, ok4=false;
  try { ok1 = hookWinHttp(); } catch (e) { console.log('[!] WinHTTP hook error:', e); }
  try { ok2 = hookWinInet(); } catch (e) { console.log('[!] WinINet hook error:', e); }
  try { ok3 = hookSChannel(); } catch (e) { console.log('[!] SChannel hook error:', e); }
  try { ok4 = hookLibcurl(); } catch (e) { console.log('[!] libcurl hook error:', e); }
  console.log('[*] Hooks ready. WinHTTP:', ok1, ' WinINet:', ok2, ' SChannel:', ok3, ' libcurl:', ok4);
  setupModuleLoadHooks();
})();
