/* PPPoker register/login trace via Frida (Windows, ASCII-only)
   Hooks WinHTTP/WinINet/SChannel/libcurl to capture plaintext HTTP for /poker/api/register.php and login.php.
   Prints full request and parsed query params (username/password/t/imei/clientvar/...)
*/

function wstr(ptr) {
  try { return ptr.isNull() ? "" : ptr.readUtf16String(); } catch (e) { return ""; }
}

function bytesToAscii(buf) {
  var u8 = new Uint8Array(buf);
  var s = "";
  for (var i = 0; i < u8.length; i++) {
    var c = u8[i];
    s += (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : '.';
  }
  return s;
}

function parseRequestAndQuery(text) {
  var out = { method: '', path: '', query: '', params: {} };
  try {
    var firstLineIdx = text.indexOf('\r\n');
    var firstLine = firstLineIdx > 0 ? text.substring(0, firstLineIdx) : text;
    // Example: GET /poker/api/register.php?username=... HTTP/1.1
    var m = firstLine.match(/^(GET|POST)\s+([^\s]+)\s+HTTP\//i);
    if (m) {
      out.method = m[1];
      out.path = m[2];
      var qIdx = out.path.indexOf('?');
      if (qIdx !== -1) out.query = out.path.substring(qIdx + 1);
    }
    var q = out.query || '';
    q.split('&').forEach(function (kv) {
      if (!kv) return;
      var eq = kv.indexOf('=');
      var k = eq === -1 ? kv : kv.substring(0, eq);
      var v = eq === -1 ? '' : kv.substring(eq + 1);
      try {
        var dk = decodeURIComponent(k.replace(/\+/g, ' '));
        var dv = decodeURIComponent(v.replace(/\+/g, ' '));
        out.params[dk] = dv;
      } catch (e) {
        out.params[k] = v;
      }
    });
  } catch (e) {}
  return out;
}

function shouldLog(s0) {
  if (!s0) return false;
  var s = s0.toString();
  return s.indexOf('register.php') !== -1 || s.indexOf('/poker/api/register.php') !== -1 || s.indexOf('login.php') !== -1 || s.indexOf('username=') !== -1;
}

var winhttpReqs = new Map();

function resolveExport(name) {
  try {
    var p = Module.findExportByName(null, name);
    if (p) return p;
    var res = new ApiResolver('module');
    var found = null;
    res.enumerateMatches('*!' + name, {
      onMatch: function (m) { if (!found) found = m; },
      onComplete: function () {}
    });
    return found ? found.address : null;
  } catch (e) {
    return null;
  }
}

function hookWinHttp() {
  var OpenReq = resolveExport('WinHttpOpenRequest');
  var SendReq = resolveExport('WinHttpSendRequest');
  if (OpenReq) {
    Interceptor.attach(OpenReq, {
      onEnter: function (args) { this.verb = wstr(args[1]); this.path = wstr(args[2]); },
      onLeave: function (rv) { try { winhttpReqs.set(rv.toString(), { verb: this.verb, path: this.path }); } catch (e) {} }
    });
  }
  if (SendReq) {
    Interceptor.attach(SendReq, {
      onEnter: function (args) {
        var hReq = args[0].toString();
        var headers = wstr(args[1]);
        var bodyPtr = args[3];
        var bodyLen = 0;
        try { bodyLen = args[4].toInt32(); } catch (e) { try { bodyLen = parseInt(args[4]); } catch (e2) { bodyLen = 0; } }
        var info = winhttpReqs.get(hReq) || { verb: '?', path: '?' };
        var body = '';
        if (!bodyPtr.isNull() && bodyLen > 0) {
          var bytes = Memory.readByteArray(bodyPtr, bodyLen);
          body = bytesToAscii(bytes);
        }
        if (shouldLog(info.path) || shouldLog(body)) {
          console.log('\n=== WinHTTP Request ===');
          console.log('Verb: ' + info.verb + '  Path: ' + info.path);
          if (headers) console.log('Headers: ' + headers);
          if (body) console.log('Body: ' + body);
          try {
            var parsed = parseRequestAndQuery('GET ' + info.path + ' HTTP/1.1');
            if (parsed.query) console.log('QueryParams: ' + JSON.stringify(parsed.params));
          } catch (e) {}
          console.log('=======================\n');
        }
      }
    });
  }
  return !!(OpenReq || SendReq);
}

function hookWinInet() {
  var OpenReqW = resolveExport('HttpOpenRequestW');
  var SendReqW = resolveExport('HttpSendRequestW');
  var inetReqs = new Map();
  if (OpenReqW) {
    Interceptor.attach(OpenReqW, {
      onEnter: function (args) { this.verb = wstr(args[1]); this.path = wstr(args[2]); },
      onLeave: function (rv) { inetReqs.set(rv.toString(), { verb: this.verb, path: this.path }); }
    });
  }
  if (SendReqW) {
    Interceptor.attach(SendReqW, {
      onEnter: function (args) {
        var hReq = args[0].toString();
        var headers = wstr(args[1]);
        var bodyPtr = args[3];
        var bodyLen = 0;
        try { bodyLen = args[4].toInt32(); } catch (e) { try { bodyLen = parseInt(args[4]); } catch (e2) { bodyLen = 0; } }
        var info = inetReqs.get(hReq) || { verb: '?', path: '?' };
        var body = '';
        if (!bodyPtr.isNull() && bodyLen > 0) {
          var bytes = Memory.readByteArray(bodyPtr, bodyLen);
          body = bytesToAscii(bytes);
        }
        if (shouldLog(info.path) || shouldLog(body)) {
          console.log('\n=== WinINet Request ===');
          console.log('Verb: ' + info.verb + '  Path: ' + info.path);
          if (headers) console.log('Headers: ' + headers);
          if (body) console.log('Body: ' + body);
          try {
            var parsed = parseRequestAndQuery('GET ' + info.path + ' HTTP/1.1');
            if (parsed.query) console.log('QueryParams: ' + JSON.stringify(parsed.params));
          } catch (e) {}
          console.log('=======================\n');
        }
      }
    });
  }
  return !!(OpenReqW || SendReqW);
}

function hookSChannel() {
  var enc = resolveExport('EncryptMessage');
  if (!enc) return false;
  Interceptor.attach(enc, {
    onEnter: function (args) {
      try {
        var pDesc = args[2];
        if (pDesc.isNull()) return;
        var cBuffers = pDesc.add(4).readU32();
        var pBuffers = pDesc.add(8).readPointer();
        var step = 8 + Process.pointerSize;
        var printed = false;
        for (var i = 0; i < cBuffers; i++) {
          var pBuf = pBuffers.add(i * step);
          var cb = pBuf.readU32();
          var type = pBuf.add(4).readU32();
          var pv = pBuf.add(8).readPointer();
          if (type === 1 && cb > 0 && !pv.isNull()) {
            var bytes = Memory.readByteArray(pv, cb);
            var s = bytesToAscii(bytes);
            if (shouldLog(s) && s.indexOf('HTTP/1.1') !== -1 && !printed) {
              printed = true;
              console.log('\n=== Schannel EncryptMessage (plaintext) ===');
              console.log(s);
              var parsed = parseRequestAndQuery(s);
              if (parsed.query) {
                console.log('QueryParams: ' + JSON.stringify(parsed.params));
                var keys = ['username','password','t','imei','clientvar','appid','os'];
                var sel = {}; keys.forEach(function (k) { if (parsed.params[k] !== undefined) sel[k] = parsed.params[k]; });
                console.log('SelectedParams: ' + JSON.stringify(sel));
              }
              console.log('==========================================\n');
            }
          }
        }
      } catch (e) {}
    }
  });
  return true;
}

// TLS plaintext hooks (UnityTLS / OpenSSL / mbedTLS)
function hookTlsWrites() {
  var hooked = false;
  function hookWrite(name, dataIndex, lenIndex, decoder) {
    var addr = resolveExport(name);
    if (!addr) return false;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          var p = args[dataIndex];
          var n = 0;
          try { n = args[lenIndex].toInt32(); } catch (e) { try { n = parseInt(args[lenIndex]); } catch (e2) { n = 0; } }
          if (!p.isNull() && n > 0 && n < 65536) {
            var bytes = Memory.readByteArray(p, n);
            var s = (decoder ? decoder(bytes) : bytesToAscii(bytes));
            if (shouldLog(s)) {
              console.log('\n=== ' + name + ' (plaintext) ===');
              console.log(s);
              var parsed = parseRequestAndQuery(s);
              if (parsed.query) {
                console.log('QueryParams: ' + JSON.stringify(parsed.params));
                var keys = ['username','password','t','imei','clientvar','appid','os'];
                var sel = {}; keys.forEach(function (k) { if (parsed.params[k] !== undefined) sel[k] = parsed.params[k]; });
                console.log('SelectedParams: ' + JSON.stringify(sel));
              }
              console.log('================================');
            }
          }
        } catch (e) {}
      }
    });
    console.log('[*] Hooked TLS write: ' + name);
    return true;
  }
  // UnityTLS
  hooked = hookWrite('unitytls_tlsctx_write', 1, 2) || hooked;
  // OpenSSL
  hooked = hookWrite('SSL_write', 1, 2) || hooked;
  // mbedTLS
  hooked = hookWrite('mbedtls_ssl_write', 1, 2) || hooked;
  return hooked;
}

// il2cpp / mono string hooks
function hookIl2CppStrings() {
  var hooked = false;
  function shouldLogString(s) {
    if (!s) return false;
    var l = s.toLowerCase();
    return l.indexOf('register.php') !== -1 || l.indexOf('/poker/api/') !== -1 || l.indexOf('login.php') !== -1 || l.indexOf('pppoker') !== -1 || l.indexOf('username=') !== -1;
  }
  
  // Il2Cpp
  var snew = resolveExport('il2cpp_string_new');
  if (snew) {
    Interceptor.attach(snew, {
      onEnter: function (args) {
        try {
          var cstr = args[0].isNull() ? '' : args[0].readCString();
          if (shouldLogString(cstr)) {
            console.log('\n=== il2cpp_string_new ===');
            console.log(cstr);
          }
        } catch (e) {}
      }
    });
    hooked = true;
    console.log('[*] Hooked il2cpp_string_new');
  }
  
  var snewlen = resolveExport('il2cpp_string_new_len');
  if (snewlen) {
    Interceptor.attach(snewlen, {
      onEnter: function (args) {
        try {
          var p = args[0]; var n = 0; try { n = args[1].toInt32(); } catch (e) { try { n = parseInt(args[1]); } catch (e2) { n = 0; } }
          if (!p.isNull() && n > 0 && n < 8192) {
            var s = p.readCString();
            if (shouldLogString(s)) {
              console.log('\n=== il2cpp_string_new_len ===');
              console.log(s);
            }
          }
        } catch (e) {}
      }
    });
    hooked = true;
    console.log('[*] Hooked il2cpp_string_new_len');
  }

  // Mono
  var mnew = resolveExport('mono_string_new');
  if (mnew) {
    Interceptor.attach(mnew, {
      onEnter: function (args) {
        try {
          // args[0] is domain (ignore), args[1] is char*
          var cstr = args[1].isNull() ? '' : args[1].readCString();
          if (shouldLogString(cstr)) {
            console.log('\n=== mono_string_new ===');
            console.log(cstr);
          }
        } catch (e) {}
      }
    });
    hooked = true;
    console.log('[*] Hooked mono_string_new');
  }

  return hooked;
}

// libcurl hooks
var curlMap = new Map();
function hookLibcurl() {
  var setopt = resolveExport('curl_easy_setopt');
  var perform = resolveExport('curl_easy_perform');
  if (!setopt && !perform) return false;
  if (setopt) {
    Interceptor.attach(setopt, {
      onEnter: function (args) {
        try {
          var easy = args[0].toString();
          var opt = args[1].toInt32();
          var val = args[2];
          var rec = curlMap.get(easy); if (!rec) { rec = { url: '', post: '' }; curlMap.set(easy, rec); }
          if (opt === 10002) { // CURLOPT_URL
            rec.url = val.isNull() ? '' : val.readUtf8String();
          } else if (opt === 10015 || opt === 10165) { // CURLOPT_POSTFIELDS / COPYPOSTFIELDS
            rec.post = val.isNull() ? '' : val.readUtf8String();
          }
        } catch (e) {}
      }
    });
  }
  if (perform) {
    Interceptor.attach(perform, {
      onEnter: function (args) {
        try {
          var easy = args[0].toString();
          var rec = curlMap.get(easy) || { url: '', post: '' };
          if (shouldLog(rec.url) || shouldLog(rec.post)) {
            console.log('\n=== libcurl easy_perform ===');
            console.log('URL: ' + rec.url);
            if (rec.post) console.log('POSTFIELDS: ' + rec.post);
            var parsed = parseRequestAndQuery('GET ' + rec.url + ' HTTP/1.1');
            if (parsed.query) {
              console.log('QueryParams: ' + JSON.stringify(parsed.params));
              var keys = ['username','password','t','imei','clientvar','appid','os'];
              var sel = {}; keys.forEach(function (k) { if (parsed.params[k] !== undefined) sel[k] = parsed.params[k]; });
              console.log('SelectedParams: ' + JSON.stringify(sel));
            }
            console.log('============================\n');
          }
        } catch (e) {}
      }
    });
  }
  return true;
}

function toLower(s) { try { return (s || '').toLowerCase(); } catch (e) { return ''; } }

function setupModuleLoadHooks() {
  function tryHookFor(modName) {
    var n = toLower(modName);
    if (n.indexOf('winhttp.dll') !== -1) { if (!globalThis.__winhttpHooked) { globalThis.__winhttpHooked = hookWinHttp(); console.log('[*] WinHTTP loaded, hooked: ' + (!!globalThis.__winhttpHooked)); } }
    if (n.indexOf('wininet.dll') !== -1) { if (!globalThis.__wininetHooked) { globalThis.__wininetHooked = hookWinInet(); console.log('[*] WinINet loaded, hooked: ' + (!!globalThis.__wininetHooked)); } }
    if (n.indexOf('secur32.dll') !== -1 || n.indexOf('schannel.dll') !== -1) { if (!globalThis.__schannelHooked) { globalThis.__schannelHooked = hookSChannel(); console.log('[*] SChannel loaded, hooked: ' + (!!globalThis.__schannelHooked)); } }
    if (n.indexOf('libcurl') !== -1 || n.indexOf('curl.dll') !== -1) { if (!globalThis.__curlHooked) { globalThis.__curlHooked = hookLibcurl(); console.log('[*] libcurl loaded, hooked: ' + (!!globalThis.__curlHooked)); } }
    if (n.indexOf('unitytls') !== -1 || n.indexOf('ssl') !== -1 || n.indexOf('mbedtls') !== -1) { if (!globalThis.__tlsHooked) { globalThis.__tlsHooked = hookTlsWrites(); console.log('[*] TLS lib loaded, hooked: ' + (!!globalThis.__tlsHooked)); } }
    if (n.indexOf('gameassembly.dll') !== -1 || n.indexOf('unityplayer.dll') !== -1) { if (!globalThis.__il2cppStrHooked) { globalThis.__il2cppStrHooked = hookIl2CppStrings(); console.log('[*] Il2Cpp strings hooked: ' + (!!globalThis.__il2cppStrHooked)); } }
  }

  try { Process.enumerateModulesSync().forEach(function (m) { tryHookFor(m.name); }); } catch (e) {}

  ['LoadLibraryW','LoadLibraryA','LoadLibraryExW'].forEach(function (fn) {
    var addr = resolveExport(fn);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          var name = (fn === 'LoadLibraryA') ? args[0].readCString() : wstr(args[0]);
          if (name) tryHookFor(name);
        } catch (e) {}
      }
    });
  });

  var ldr = resolveExport('LdrLoadDll');
  if (ldr) {
    Interceptor.attach(ldr, {
      onEnter: function (args) {
        try {
          var pustr = args[2];
          if (!pustr.isNull()) {
            var len = pustr.readU16();
            var buf = pustr.add(8).readPointer();
            var name = buf.readUtf16String(len/2);
            if (name) tryHookFor(name);
          }
        } catch (e) {}
      }
    });
  }
}

// Helper to find module case-insensitively
function findModule(name) {
  var mods = Process.enumerateModules();
  var lower = name.toLowerCase();
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === lower) return mods[i];
  }
  return null;
}

// Helper to find exports fuzzily
function findExportLikely(modName, pattern) {
  var m = findModule(modName);
  if (!m) return null;
  var exports = m.enumerateExports();
  for (var i = 0; i < exports.length; i++) {
    if (exports[i].name.indexOf(pattern) !== -1) return exports[i].address;
  }
  return null;
}

// Debug: dump exports of a module to see if we can access them
function dumpExportsSample(modName) {
  var m = findModule(modName);
  if (!m) { console.log('[DEBUG] Module ' + modName + ' not found.'); return; }
  console.log('[DEBUG] Exports sample for ' + m.name + ':');
  var ex = m.enumerateExports().slice(0, 5);
  ex.forEach(function(e) { console.log(' - ' + e.name); });
  if (ex.length === 0) console.log(' - (No exports found)');
}

// Periodic poller to detect modules and symbols that load late
function startPoller() {
  var interval = setInterval(function () {
    var targetMods = ['gameassembly.dll', 'unityplayer.dll', 'winhttp.dll', 'wininet.dll', 'ws2_32.dll', 'secur32.dll', 'libcurl.dll', 'user32.dll'];
    
    // Try hooking standard networking if not yet hooked
    if (!globalThis.__winhttpHooked) {
      var addr = resolveExport('WinHttpOpenRequest') || findExportLikely('WINHTTP.dll', 'WinHttpOpenRequest');
      if (addr) {
        globalThis.__winhttpHooked = hookWinHttp();
        console.log('[POLL] WinHTTP hooked: ' + globalThis.__winhttpHooked);
      } else if (findModule('WINHTTP.dll') && !globalThis.__dumped_winhttp) {
         // Force dump exports
         var m = findModule('WINHTTP.dll');
         console.log('[DEBUG] Dumping exports for ' + m.name + ' (base: ' + m.base + '):');
         var ex = m.enumerateExports();
         console.log('[DEBUG] Total exports: ' + ex.length);
         for(var i=0; i<Math.min(ex.length, 10); i++) console.log(' - ' + ex[i].name + ' @ ' + ex[i].address);
         globalThis.__dumped_winhttp = true;
      }
    }
    if (!globalThis.__wininetHooked) {
      var addr = resolveExport('HttpOpenRequestW') || findExportLikely('wininet.dll', 'HttpOpenRequestW');
      if (addr) {
        globalThis.__wininetHooked = hookWinInet();
        console.log('[POLL] WinINet hooked: ' + globalThis.__wininetHooked);
      }
    }
    if (!globalThis.__schannelHooked) {
      var addr = resolveExport('EncryptMessage') || findExportLikely('secur32.dll', 'EncryptMessage');
      if (addr) {
        globalThis.__schannelHooked = hookSChannel();
        console.log('[POLL] SChannel hooked: ' + globalThis.__schannelHooked);
      }
    }
    
    // Try hooking Il2Cpp / Mono with fuzzy search
    if (!globalThis.__il2cppStrHooked) {
      var il2cpp_new = resolveExport('il2cpp_string_new') || findExportLikely('GameAssembly.dll', 'il2cpp_string_new') || findExportLikely('UnityPlayer.dll', 'il2cpp_string_new');
      var mono_new = resolveExport('mono_string_new') || findExportLikely('mono-2.0-bdwgc.dll', 'mono_string_new');
      
      if (il2cpp_new || mono_new) {
        globalThis.__il2cppStrHooked = hookIl2CppStrings();
        console.log('[POLL] Il2Cpp/Mono strings hooked: ' + globalThis.__il2cppStrHooked);
      } else {
        // Debug: list exports of GameAssembly once to see if symbols exist
        var ga = Process.findModuleByName('GameAssembly.dll');
        if (ga && !globalThis.__ga_dumped) {
          console.log('[DEBUG] GameAssembly found. Exports sample:');
          var ex = ga.enumerateExports().slice(0, 10);
          ex.forEach(function(e){ console.log(' - ' + e.name); });
          globalThis.__ga_dumped = true;
        }
      }
    }
    
    // Try hooking TLS writes if symbols appear
    if (!globalThis.__tlsHooked) {
      if (resolveExport('unitytls_tlsctx_write') || resolveExport('SSL_write') || resolveExport('mbedtls_ssl_write')) {
        globalThis.__tlsHooked = hookTlsWrites();
        console.log('[POLL] TLS writes hooked: ' + globalThis.__tlsHooked);
      }
    }
    
    // Log loaded interesting modules once
    targetMods.forEach(function(tm) {
      var m = Process.findModuleByName(tm);
      if (m && !globalThis['__logged_' + tm]) {
        console.log('[POLL] Found module: ' + m.name + ' Base: ' + m.base);
        globalThis['__logged_' + tm] = true;
      }
    });

  }, 1000);
}

(function main() {
  console.log('[*] Starting hooks & poller...');
  var ok1=false, ok2=false, ok3=false, ok4=false, ok5=false, ok6=false;
  try { ok1 = hookWinHttp(); } catch (e) {}
  try { ok2 = hookWinInet(); } catch (e) {}
  try { ok3 = hookSChannel(); } catch (e) {}
  try { ok4 = hookLibcurl(); } catch (e) {}
  try { ok5 = hookTlsWrites(); } catch (e) {}
  try { ok6 = hookIl2CppStrings(); } catch (e) {}
  
  console.log('[*] Initial Hook State -> WinHTTP:' + ok1 + ' WinINet:' + ok2 + ' SChannel:' + ok3 + ' Curl:' + ok4 + ' TLS:' + ok5 + ' Il2Cpp:' + ok6);
  
  setupModuleLoadHooks();
  startPoller();
})();
