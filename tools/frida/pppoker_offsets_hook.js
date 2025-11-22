// Hook specific GameAssembly.dll methods by RVA to intercept Register/Login params
// Based on dump.cs analysis

const RVA_RegisterEmailAccount = 0x2895F90; 
const RVA_Login                = 0x28933D0; 
const RVA_WWWForm_AddField     = 0x4F5D910; 
const RVA_HttpRequest_PostForm = 0x236AAE0; // HttpRequest.PostForm(uri, string formData, ...)
const RVA_UnityWebRequest_Post = 0x4F59100; // UnityWebRequest.Post(uri, string postData)
const RVA_UnityWebRequest_Post_UriStr = 0x4F59190; // UnityWebRequest.Post(Uri uri, string postData)
const RVA_UnityWebRequest_Post_WWWForm_str = 0x4F59530; // UnityWebRequest.Post(string uri, WWWForm formData)
const RVA_UnityWebRequest_Post_WWWForm_uri = 0x4F59360; // UnityWebRequest.Post(Uri uri, WWWForm formData)
const RVA_UnityWebRequest_Post_List_str = 0x4F59220; // UnityWebRequest.Post(string uri, List<IMultipartFormSection>)
const RVA_UnityWebRequest_Post_List_uri = 0x4F59490; // UnityWebRequest.Post(Uri uri, List<IMultipartFormSection>)
const RVA_HttpUtility_WebGetAsync = 0x2DFABA0; // HttpUtility.WebGetAsync(string url, ...)
const RVA_HttpUtility_WebPostAsync = 0x2DFACC0; // HttpUtility.WebPostAsync(string url, WWWForm form, ...)
const RVA_get_RegisterUrl        = 0x2896D70; // get_RegisterUrl()
const RVA_HttpRequest_Post_WWWForm = 0x236ACA0; // HttpRequest.Post(string uri, WWWForm formData, ...)
const RVA_HttpRequest_BuildPostRequest_WWWForm = 0x2368980; // private HttpRequest BuildPostRequest(string uri, WWWForm formData,...)
const RVA_HttpRequest_BuildPostFormRequest = 0x2368800; // private HttpRequest BuildPostFormRequest(string uri, string formData,...)
const RVA_UnityWebRequest_SetupPostWwwForm = 0x4F5AC10; // private static void SetupPostWwwForm(UnityWebRequest request, string postData)
const RVA_UnityWebRequest_SetupPost       = 0x4F593F0;  // private static void SetupPost(UnityWebRequest request, string postData, string contentType)
const RVA_UploadHandlerRaw_Create         = 0x4F5CD10; // private static IntPtr Create(UploadHandlerRaw self, byte* data, int dataLength)
const RVA_UploadHandlerRaw_Ctor_ByteArr   = 0x4F5CE60; // public void .ctor(byte[] data)
const RVA_UploadHandlerRaw_Ctor_NativeArr = 0x4F5D0D0; // public void .ctor(NativeArray<byte> data, bool transferOwnership)
const RVA_UploadHandlerRaw_Ctor_ReadOnly  = 0x4F5CFD0; // public void .ctor(NativeArray.ReadOnly<byte> data)
const RVA_UnityWebRequest_Get_str         = 0x4F58B20; // UnityWebRequest.Get(string uri)
const RVA_UnityWebRequest_Get_uri         = 0x4F57EF0; // UnityWebRequest.Get(Uri uri)

// CryptoUtil (PP.PPPoker.CryptoUtil) helpers from dump.cs
const RVA_CryptoUtil_CryptoPassword        = 0x2DF57B0; // public static string CryptoPassword(string password)
const RVA_CryptoUtil_CryptoPasswordV2      = 0x2DF5680; // public static string CryptoPasswordV2(string password)
const RVA_CryptoUtil_XXTeaEncodeForHttp    = 0x2DF6340; // public static (string,long) XXTeaEncodeForHttp(string data)
const RVA_CryptoUtil_XXTeaDecodeForHttp    = 0x2DF6210; // public static string XXTeaDecodeForHttp(string data, int timestamp)
const RVA_CryptoUtil_EncryptLocalPassword  = 0x2DF58E0; // public static string EncryptLocalPassword(string password)
const RVA_CryptoUtil_DecryptLocalPassword  = 0x2DF5850; // public static string DecryptLocalPassword(string encryptedPassword)
const RVA_CryptoUtil__CryptoPassword       = 0x2DF64F0; // private static string _CryptoPassword(string password)
const RVA_CryptoUtil__XXTeaEncodeForHttp   = 0x2DF6650; // private static (string,long) _XXTeaEncodeForHttp(string data)
const RVA_CryptoUtil__XXTeaDecodeForHttp   = 0x2DF6550; // private static string _XXTeaDecodeForHttp(string data, int timestamp)
const RVA_CryptoUtil_GetCryptoSuffix       = 0x2DF5970; // private static string GetCryptoSuffix()
const RVA_CryptoUtil_GetHttpCryptoKey      = 0x2DF5A20; // private static string GetHttpCryptoKey(Nullable<long> timestamp)
const RVA_CryptoUtil_GetLocalPasswordKey   = 0x2DF5EB0; // private static string GetLocalPasswordKey()

// Native HTTP logging toggles
var LOG_NATIVE_HTTP = true; // log URLs via curl/winhttp even if managed hooks miss them

function readIl2CppString(ptr) {
  try {
    if (ptr.isNull()) return null;
    // Il2CppString: [ObjectHeader] + [length(4)] + [chars...]
    // But usually arguments passed as string* in ABI are pointers to Il2CppString object.
    // Header size is typically 0x10 (monitor + klass). length at +0x10. chars at +0x14 (UTF-16).
    // Let's try reading length at +0x10.
    const len = ptr.add(0x10).readU32();
    if (len > 1024) return ""; // sanity check
    return ptr.add(0x14).readUtf16String(len);
  } catch (e) {
    return "";
  }
}

function hookGameAssembly() {
  const ga = Process.findModuleByName("GameAssembly.dll");
  if (!ga) {
    console.log("[!] GameAssembly.dll not found yet.");
    return false;
  }
  console.log("[*] GameAssembly.dll base: " + ga.base);

  // 1. Hook RegisterEmailAccount
  const ptrReg = ga.base.add(RVA_RegisterEmailAccount);
  Interceptor.attach(ptrReg, {
    onEnter: function(args) {
      try {
        // args[0] = this
        // args[1] = userName (Il2CppString*)
        // args[2] = password (Il2CppString*)
        const user = readIl2CppString(args[1]);
        const pass = readIl2CppString(args[2]);
        console.log("\n=== RegisterEmailAccount called ===");
        console.log("Username: " + user);
        console.log("Password: " + pass);
        console.log("===================================\n");
      } catch (e) {
        console.log("Error reading RegisterEmailAccount args: " + e);
      }
    }
  });
  console.log("[*] Hooked RegisterEmailAccount at " + ptrReg);

  // 2. Hook WWWForm.AddField
  const ptrAdd = ga.base.add(RVA_WWWForm_AddField);
  Interceptor.attach(ptrAdd, {
    onEnter: function(args) {
      try {
        // args[0] = this
        // args[1] = fieldName (Il2CppString*)
        // args[2] = value (Il2CppString*)
        const name = readIl2CppString(args[1]);
        const val = readIl2CppString(args[2]);
        
        // Filter interesting fields
        if (name && (name.indexOf("username") !== -1 || name.indexOf("password") !== -1 || name.indexOf("imei") !== -1 || name.indexOf("t") === 0)) {
           console.log("WWWForm.AddField: " + name + " = " + val);
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked WWWForm.AddField at " + ptrAdd);

  // 3. Hook Login
  const ptrLogin = ga.base.add(RVA_Login);
  Interceptor.attach(ptrLogin, {
    onEnter: function(args) {
      try {
        // args[0] = this
        // args[1] = nType (int)
        // args[2] = szUsername (Il2CppString*)
        // args[3] = szPassword (Il2CppString*)
        const user = readIl2CppString(args[2]);
        const pass = readIl2CppString(args[3]);
        console.log("\n=== Login method called ===");
        console.log("Username: " + user);
        console.log("Password: " + pass);
        console.log("===========================\n");

        // FORCE: invoke RegisterEmailAccount one-shot to trigger register.php building (dry)
        if (FORCE_REG_ON_LOGIN && !globalThis.__force_reg_done) {
          globalThis.__force_reg_done = true;
          try {
            const RegFn = new NativeFunction(ga.base.add(RVA_RegisterEmailAccount), 'pointer', ['pointer','pointer','pointer','pointer']);
            const ret = RegFn(args[0], args[2], args[3], ptr(0));
            console.log('[FORCE] RegisterEmailAccount invoked (dry). Ret=' + ret);
          } catch (e) {
            console.log('[FORCE] Error invoking RegisterEmailAccount: ' + e);
          }
        }
      } catch (e) {
        console.log("Error reading Login args: " + e);
      }
    }
  });
  console.log("[*] Hooked Login at " + ptrLogin);

  // 4. Hook HttpRequest.PostForm
  const ptrPostForm = ga.base.add(RVA_HttpRequest_PostForm);
  Interceptor.attach(ptrPostForm, {
    onEnter: function(args) {
      try {
        // static method?
        // args[0] = uri (string)
        // args[1] = formData (string)
        const uri = readIl2CppString(args[0]);
        const data = readIl2CppString(args[1]);
        console.log("\n=== HttpRequest.PostForm ===");
        console.log("URI: " + uri);
        console.log("Data: " + data);
        console.log("============================\n");
      } catch (e) {}
    }
  });
  console.log("[*] Hooked HttpRequest.PostForm at " + ptrPostForm);

  // 5. Hook UnityWebRequest.Post (string, string)
  const ptrUWRPost = ga.base.add(RVA_UnityWebRequest_Post);
  Interceptor.attach(ptrUWRPost, {
    onEnter: function(args) {
      try {
        const uri = readIl2CppString(args[0]);
        const data = readIl2CppString(args[1]);
        if (uri && (uri.indexOf("login.php") !== -1 || uri.indexOf("register.php") !== -1)) {
            console.log("\n=== UnityWebRequest.Post (str,str) ===");
            console.log("URI: " + uri);
            console.log("Data: " + data);
            console.log("============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Post (str,str) at " + ptrUWRPost);

  // 5a. UnityWebRequest.Post (Uri, string)
  const ptrUWRPostUriStr = ga.base.add(RVA_UnityWebRequest_Post_UriStr);
  Interceptor.attach(ptrUWRPostUriStr, {
    onEnter: function(args) {
      try {
        const data = readIl2CppString(args[1]);
        // args[0] is a Uri object; skip decoding, log only data
        console.log("\n=== UnityWebRequest.Post (Uri,str) === Data: " + data + "\n============================\n");
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Post (Uri,str) at " + ptrUWRPostUriStr);

  // 5b. UnityWebRequest.Post (string, WWWForm)
  const ptrUwrPostWwwFormStr = ga.base.add(RVA_UnityWebRequest_Post_WWWForm_str);
  Interceptor.attach(ptrUwrPostWwwFormStr, {
    onEnter: function(args) {
      try {
        const uri = readIl2CppString(args[0]);
        if (uri && (uri.indexOf('login.php') !== -1 || uri.indexOf('register.php') !== -1)) {
          console.log("\n=== UnityWebRequest.Post (WWWForm,string) ===\nURI: " + uri + "\n============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Post (WWWForm,string) at " + ptrUwrPostWwwFormStr);

  // 5c. UnityWebRequest.Post (Uri, WWWForm)
  const ptrUwrPostWwwFormUri = ga.base.add(RVA_UnityWebRequest_Post_WWWForm_uri);
  Interceptor.attach(ptrUwrPostWwwFormUri, {
    onEnter: function(args) {
      try {
        console.log("\n=== UnityWebRequest.Post (WWWForm,Uri) ===\n[Uri overload]\n============================\n");
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Post (WWWForm,Uri) at " + ptrUwrPostWwwFormUri);

  // 5d. UnityWebRequest.Post (string, List<IMultipartFormSection>)
  const ptrUwrPostListStr = ga.base.add(RVA_UnityWebRequest_Post_List_str);
  Interceptor.attach(ptrUwrPostListStr, {
    onEnter: function(args) {
      try {
        const uri = readIl2CppString(args[0]);
        if (uri && (uri.indexOf('login.php') !== -1 || uri.indexOf('register.php') !== -1)) {
          console.log("\n=== UnityWebRequest.Post (List,str) ===\nURI: " + uri + "\n============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Post (List,str) at " + ptrUwrPostListStr);

  // 5e. UnityWebRequest.Post (Uri, List<IMultipartFormSection>)
  const ptrUwrPostListUri = ga.base.add(RVA_UnityWebRequest_Post_List_uri);
  Interceptor.attach(ptrUwrPostListUri, {
    onEnter: function(args) {
      try {
        console.log("\n=== UnityWebRequest.Post (List,Uri) ===\n[Uri overload]\n============================\n");
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Post (List,Uri) at " + ptrUwrPostListUri);

  // 6. Hook HttpUtility.WebGetAsync (captures full GET URL)
  const ptrWebGet = ga.base.add(RVA_HttpUtility_WebGetAsync);
  Interceptor.attach(ptrWebGet, {
    onEnter: function(args) {
      try {
        const url = readIl2CppString(args[0]);
        if (url && (url.indexOf("register.php") !== -1 || url.indexOf("login.php") !== -1)) {
          console.log("\n=== HttpUtility.WebGetAsync ===");
          console.log("URL: " + url);
          try {
            const qIdx = url.indexOf('?');
            if (qIdx !== -1) {
              const q = url.substring(qIdx+1);
              const params = {};
              q.split('&').forEach(function(kv){ if(!kv)return; var eq=kv.indexOf('='); var k=eq==-1?kv:kv.substring(0,eq); var v=eq==-1?'':kv.substring(eq+1); try{params[decodeURIComponent(k)]=decodeURIComponent(v);}catch(e){params[k]=v;} });
              console.log("Params: " + JSON.stringify(params));
              var sel = {}; ['username','password','t','imei','clientvar','appid','os'].forEach(function(k){ if (params[k]!==undefined) sel[k]=params[k]; });
              console.log("Selected: " + JSON.stringify(sel));
            }
          } catch (e) {}
          console.log("===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked HttpUtility.WebGetAsync at " + ptrWebGet);

  // 6b. Hook HttpUtility.WebPostAsync (captures POST URL)
  const ptrWebPost = ga.base.add(RVA_HttpUtility_WebPostAsync);
  Interceptor.attach(ptrWebPost, {
    onEnter: function(args) {
      try {
        const url = readIl2CppString(args[0]); // string url
        if (url && (url.indexOf('login.php') !== -1 || url.indexOf('register.php') !== -1)) {
          console.log("\n=== HttpUtility.WebPostAsync ===");
          console.log("URL: " + url);
          console.log("Form: [WWWForm object] (fields will appear via WWWForm.AddField hooks if used)");
          console.log("===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked HttpUtility.WebPostAsync at " + ptrWebPost);

  // 7. Hook get_RegisterUrl to see exact endpoint
  const ptrGetRegUrl = ga.base.add(RVA_get_RegisterUrl);
  Interceptor.attach(ptrGetRegUrl, {
    onLeave: function(retval) {
      try {
        const s = readIl2CppString(retval);
        if (s) {
          console.log("[get_RegisterUrl] => " + s);
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked get_RegisterUrl at " + ptrGetRegUrl);

  // 8. Hook HttpRequest.Post (WWWForm)
  const ptrHttpPostWWW = ga.base.add(RVA_HttpRequest_Post_WWWForm);
  Interceptor.attach(ptrHttpPostWWW, {
    onEnter: function(args) {
      try {
        const uri = readIl2CppString(args[0]);
        if (uri && (uri.indexOf('login.php') !== -1 || uri.indexOf('register.php') !== -1)) {
          console.log("\n=== HttpRequest.Post (WWWForm) ===\nURI: " + uri + "\n===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked HttpRequest.Post (WWWForm) at " + ptrHttpPostWWW);

  // 9. Hook HttpRequest.BuildPostRequest (WWWForm)
  const ptrBuildPostWWW = ga.base.add(RVA_HttpRequest_BuildPostRequest_WWWForm);
  Interceptor.attach(ptrBuildPostWWW, {
    onEnter: function(args) {
      try {
        const uri = readIl2CppString(args[0]);
        if (uri && (uri.indexOf('login.php') !== -1 || uri.indexOf('register.php') !== -1)) {
          console.log("\n=== HttpRequest.BuildPostRequest (WWWForm) ===\nURI: " + uri + "\n===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked HttpRequest.BuildPostRequest (WWWForm) at " + ptrBuildPostWWW);

  // 10. Hook HttpRequest.BuildPostFormRequest (string)
  const ptrBuildPostForm = ga.base.add(RVA_HttpRequest_BuildPostFormRequest);
  Interceptor.attach(ptrBuildPostForm, {
    onEnter: function(args) {
      try {
        const uri = readIl2CppString(args[0]);
        const data = readIl2CppString(args[1]);
        if (uri && (uri.indexOf('login.php') !== -1 || uri.indexOf('register.php') !== -1)) {
          console.log("\n=== HttpRequest.BuildPostFormRequest ===\nURI: " + uri + "\nData: " + data + "\n===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked HttpRequest.BuildPostFormRequest at " + ptrBuildPostForm);

  // 11. Hook UnityWebRequest.SetupPostWwwForm to capture body
  const ptrSetupPostWww = ga.base.add(RVA_UnityWebRequest_SetupPostWwwForm);
  Interceptor.attach(ptrSetupPostWww, {
    onEnter: function(args) {
      try {
        const postData = readIl2CppString(args[1]);
        if (postData && (postData.indexOf('login.php') !== -1 || postData.indexOf('username=') !== -1)) {
          console.log("\n=== SetupPostWwwForm ===\nPostData: " + postData + "\n===============================\n");
        } else if (postData) {
          console.log("\n=== SetupPostWwwForm ===\nPostData: " + postData + "\n===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.SetupPostWwwForm at " + ptrSetupPostWww);

  // 12. Hook UnityWebRequest.SetupPost to capture body/contentType
  const ptrSetupPost = ga.base.add(RVA_UnityWebRequest_SetupPost);
  Interceptor.attach(ptrSetupPost, {
    onEnter: function(args) {
      try {
        const postData = readIl2CppString(args[1]);
        const contentType = readIl2CppString(args[2]);
        if (postData && (postData.indexOf('login.php') !== -1 || postData.indexOf('username=') !== -1)) {
          console.log("\n=== SetupPost ===\nContent-Type: " + contentType + "\nPostData: " + postData + "\n===============================\n");
        } else if (postData) {
          console.log("\n=== SetupPost ===\nContent-Type: " + contentType + "\nPostData: " + postData + "\n===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.SetupPost at " + ptrSetupPost);

  // 13. Hook UploadHandlerRaw.Create (has raw pointer + length)
  const ptrUplCreate = ga.base.add(RVA_UploadHandlerRaw_Create);
  Interceptor.attach(ptrUplCreate, {
    onEnter: function(args) {
      try {
        const p = args[1];
        var n = 0; try { n = args[2].toInt32(); } catch (e) { try { n = parseInt(args[2]); } catch (e2) { n = 0; } }
        if (!p.isNull() && n > 0 && n < 65536) {
          const bytes = Memory.readByteArray(p, n);
          const s = bytesToAscii(bytes);
          if (s.indexOf('username=') !== -1 || s.indexOf('login.php') !== -1 || s.indexOf('register.php') !== -1) {
            console.log("\n=== UploadHandlerRaw.Create (body) ===\n" + s + "\n===============================\n");
          }
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UploadHandlerRaw.Create at " + ptrUplCreate);

  // 14. Hook UploadHandlerRaw..ctor(byte[])
  const ptrUplCtorBA = ga.base.add(RVA_UploadHandlerRaw_Ctor_ByteArr);
  Interceptor.attach(ptrUplCtorBA, {
    onEnter: function(args) {
      try {
        const arr = args[1];
        if (arr && !arr.isNull()) {
          const len = arr.add(0x18).readU32();
          const dataPtr = arr.add(0x20);
          if (len > 0 && len < 65536) {
            const bytes = Memory.readByteArray(dataPtr, len);
            const s = bytesToAscii(bytes);
            if (s.indexOf('username=') !== -1 || s.indexOf('login.php') !== -1 || s.indexOf('register.php') !== -1) {
              console.log("\n=== UploadHandlerRaw..ctor(byte[]) ===\n" + s + "\n===============================\n");
            }
          }
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UploadHandlerRaw..ctor(byte[]) at " + ptrUplCtorBA);

  // 15. UnityWebRequest.Get(string)
  const ptrGetStr = ga.base.add(RVA_UnityWebRequest_Get_str);
  Interceptor.attach(ptrGetStr, {
    onEnter: function(args) {
      try {
        const uri = readIl2CppString(args[0]);
        if (uri && (uri.indexOf('register.php') !== -1 || uri.indexOf('login.php') !== -1)) {
          console.log("\n=== UnityWebRequest.Get (string) ===\nURI: " + uri + "\n===============================\n");
        }
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Get(string) at " + ptrGetStr);

  // 16. UnityWebRequest.Get(Uri)
  const ptrGetUri = ga.base.add(RVA_UnityWebRequest_Get_uri);
  Interceptor.attach(ptrGetUri, {
    onEnter: function(args) {
      try {
        console.log("\n=== UnityWebRequest.Get (Uri) ===\n[Uri overload]\n===============================\n");
      } catch (e) {}
    }
  });
  console.log("[*] Hooked UnityWebRequest.Get(Uri) at " + ptrGetUri);

  // 17. CryptoUtil helpers: observe password & HTTP XXTEA pipeline
  try {
    const ptrCryptoPwd = ga.base.add(RVA_CryptoUtil_CryptoPassword);
    Interceptor.attach(ptrCryptoPwd, {
      onEnter: function(args) {
        try { console.log('\n[CryptoUtil.CryptoPassword] in=' + readIl2CppString(args[0]) + '\n'); } catch (e) {}
      },
      onLeave: function(retval) {
        try { console.log('[CryptoUtil.CryptoPassword] out=' + readIl2CppString(retval)); } catch (e) {}
      }
    });
    console.log('[*] Hooked CryptoUtil.CryptoPassword at ' + ptrCryptoPwd);
  } catch (e) {}
  try {
    const ptrCryptoPwdV2 = ga.base.add(RVA_CryptoUtil_CryptoPasswordV2);
    Interceptor.attach(ptrCryptoPwdV2, {
      onEnter: function(args) {
        try { console.log('\n[CryptoUtil.CryptoPasswordV2] in=' + readIl2CppString(args[0]) + '\n'); } catch (e) {}
      },
      onLeave: function(retval) {
        try { console.log('[CryptoUtil.CryptoPasswordV2] out=' + readIl2CppString(retval)); } catch (e) {}
      }
    });
    console.log('[*] Hooked CryptoUtil.CryptoPasswordV2 at ' + ptrCryptoPwdV2);
  } catch (e) {}
  try {
    const ptrGetSuffix = ga.base.add(RVA_CryptoUtil_GetCryptoSuffix);
    Interceptor.attach(ptrGetSuffix, {
      onLeave: function(retval) {
        try { console.log('[CryptoUtil.GetCryptoSuffix] => ' + readIl2CppString(retval)); } catch (e) {}
      }
    });
    console.log('[*] Hooked CryptoUtil.GetCryptoSuffix at ' + ptrGetSuffix);
  } catch (e) {}
  try {
    const ptrGetHttpKey = ga.base.add(RVA_CryptoUtil_GetHttpCryptoKey);
    Interceptor.attach(ptrGetHttpKey, {
      onEnter: function(args) {
        try { console.log('[CryptoUtil.GetHttpCryptoKey] arg timestamp? raw=' + args[0]); } catch (e) {}
      },
      onLeave: function(retval) {
        try { console.log('[CryptoUtil.GetHttpCryptoKey] => ' + readIl2CppString(retval)); } catch (e) {}
      }
    });
    console.log('[*] Hooked CryptoUtil.GetHttpCryptoKey at ' + ptrGetHttpKey);
  } catch (e) {}
  try {
    const ptrLocalKey = ga.base.add(RVA_CryptoUtil_GetLocalPasswordKey);
    Interceptor.attach(ptrLocalKey, {
      onLeave: function(retval) {
        try { console.log('[CryptoUtil.GetLocalPasswordKey] => ' + readIl2CppString(retval)); } catch (e) {}
      }
    });
    console.log('[*] Hooked CryptoUtil.GetLocalPasswordKey at ' + ptrLocalKey);
  } catch (e) {}
  try {
    const ptrXXTeaHttp = ga.base.add(RVA_CryptoUtil_XXTeaEncodeForHttp);
    Interceptor.attach(ptrXXTeaHttp, {
      onEnter: function(args) {
        try { console.log('\n[CryptoUtil.XXTeaEncodeForHttp] data=' + readIl2CppString(args[0]) + '\n'); } catch (e) {}
      }
    });
    console.log('[*] Hooked CryptoUtil.XXTeaEncodeForHttp at ' + ptrXXTeaHttp);
  } catch (e) {}
  try {
    const ptrXXTeaHttpPriv = ga.base.add(RVA_CryptoUtil__XXTeaEncodeForHttp);
    Interceptor.attach(ptrXXTeaHttpPriv, {
      onEnter: function(args) {
        try { console.log('\n[CryptoUtil._XXTeaEncodeForHttp] data=' + readIl2CppString(args[0]) + '\n'); } catch (e) {}
      }
    });
    console.log('[*] Hooked CryptoUtil._XXTeaEncodeForHttp at ' + ptrXXTeaHttpPriv);
  } catch (e) {}

  // DRY-RUN: block outgoing network across common stacks (libcurl / WinHTTP)
  if (DRY_RUN_BLOCK_NET) {
    try {
      const curlPerform = Module.findExportByName(null, 'curl_easy_perform');
      if (curlPerform && !globalThis.__curl_blocked) {
        Interceptor.replace(curlPerform, new NativeCallback(function(easy){
          console.log('[DRY-RUN] curl_easy_perform blocked');
          return 7; // CURLE_COULDNT_CONNECT
        }, 'int', ['pointer']));
        globalThis.__curl_blocked = true;
      }
    } catch (e) {}
    try {
      const winSend = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
      if (winSend && !globalThis.__winhttp_blocked) {
        Interceptor.replace(winSend, new NativeCallback(function(){
          console.log('[DRY-RUN] WinHttpSendRequest blocked');
          return 0; // FALSE
        }, 'int', ['pointer','pointer','uint','pointer','uint','uint','pointer']));
        globalThis.__winhttp_blocked = true;
      }
    } catch (e) {}
  }

  // Native HTTP URL/body logging (curl & WinHTTP & WinINet)
  if (LOG_NATIVE_HTTP) {
    try {
      // curl_easy_setopt(handle, option, param)
      const curlSetopt = Module.findExportByName(null, 'curl_easy_setopt');
      if (curlSetopt && !globalThis.__curl_setopt_hooked) {
        Interceptor.attach(curlSetopt, {
          onEnter: function(args) {
            try {
              const opt = args[1].toInt32 ? args[1].toInt32() : parseInt(args[1]);
              // CURLOPT_URL = 10002, CURLOPT_POSTFIELDS = 10015, CURLOPT_COPYPOSTFIELDS = 10165
              if (opt === 10002 || opt === 10015 || opt === 10165) {
                let val = null;
                try { val = args[2].readUtf8String(); } catch (_) {}
                if (val) {
                  if (opt === 10002) {
                    if (val.indexOf('register.php') !== -1 || val.indexOf('login.php') !== -1) {
                      console.log('[curl_setopt URL] ' + val);
                    }
                  } else {
                    if (val.indexOf('username=') !== -1 || val.indexOf('token=') !== -1) {
                      console.log('[curl_setopt POSTFIELDS] ' + val);
                    }
                  }
                }
              }
            } catch (e) {}
          }
        });
        globalThis.__curl_setopt_hooked = true;
      }
    } catch (e) {}
    try {
      // Track WinHTTP connection -> host mapping
      const connMap = {};
      const whConnect = Module.findExportByName('winhttp.dll', 'WinHttpConnect');
      if (whConnect && !globalThis.__winhttp_connect_hooked) {
        Interceptor.attach(whConnect, {
          onEnter: function(args) {
            this.hSession = args[0];
            this.host = '';
            try { this.host = args[1].readUtf16String(); } catch (_) {}
            this.port = 0; try { this.port = args[2].toInt32(); } catch (_) {}
          },
          onLeave: function(retval) {
            try {
              if (!retval.isNull() && this.host) {
                connMap[retval.toString()] = { host: this.host, port: this.port };
              }
            } catch (_) {}
          }
        });
        globalThis.__winhttp_connect_hooked = true;
      }
      const whOpenReq = Module.findExportByName('winhttp.dll', 'WinHttpOpenRequest');
      if (whOpenReq && !globalThis.__winhttp_openreq_hooked) {
        Interceptor.attach(whOpenReq, {
          onEnter: function(args) {
            try {
              const hConnect = args[0];
              const verb = args[1].isNull() ? '' : args[1].readUtf16String();
              const obj = args[2].isNull() ? '' : args[2].readUtf16String(); // path + query
              const info = connMap[hConnect.toString()];
              const hostPort = info ? (info.host + (info.port ? (':' + info.port) : '')) : '';
              if (obj.indexOf('register.php') !== -1 || obj.indexOf('login.php') !== -1) {
                console.log('[WinHttpOpenRequest] ' + verb + ' https://' + hostPort + obj);
              }
            } catch (e) {}
          }
        });
        globalThis.__winhttp_openreq_hooked = true;
      }
      const whSend = Module.findExportByName('winhttp.dll', 'WinHttpSendRequest');
      if (whSend && !globalThis.__winhttp_send_log_hooked) {
        Interceptor.attach(whSend, {
          onEnter: function(args) {
            try {
              const headers = args[1].isNull() ? null : args[1].readUtf16String();
              const total = args[5].toInt32 ? args[5].toInt32() : 0;
              if (headers && (headers.indexOf('register.php') !== -1 || headers.indexOf('login.php') !== -1)) {
                console.log('[WinHttpSendRequest headers] ' + headers);
              }
              if (total > 0) {
                console.log('[WinHttpSendRequest] data length: ' + total);
              }
            } catch (e) {}
          }
        });
        globalThis.__winhttp_send_log_hooked = true;
      }
    } catch (e) {}
    try {
      // WinINet hooks (alternative stack used by Unity on Windows)
      const inetConnMap = {};
      const InternetConnectW = Module.findExportByName('wininet.dll', 'InternetConnectW');
      if (InternetConnectW && !globalThis.__wininet_connect_hooked) {
        Interceptor.attach(InternetConnectW, {
          onEnter: function(args) {
            this.hInternet = args[0];
            this.server = '';
            try { this.server = args[1].readUtf16String(); } catch (_) {}
            this.port = 0; try { this.port = args[2].toInt32(); } catch (_) {}
          },
          onLeave: function(retval) {
            try {
              if (!retval.isNull() && this.server) {
                inetConnMap[retval.toString()] = { host: this.server, port: this.port };
              }
            } catch (_) {}
          }
        });
        globalThis.__wininet_connect_hooked = true;
      }
      const HttpOpenRequestW = Module.findExportByName('wininet.dll', 'HttpOpenRequestW');
      if (HttpOpenRequestW && !globalThis.__wininet_openreq_hooked) {
        Interceptor.attach(HttpOpenRequestW, {
          onEnter: function(args) {
            try {
              const hConnect = args[0];
              const verb = args[1].isNull() ? '' : args[1].readUtf16String();
              const obj = args[2].isNull() ? '' : args[2].readUtf16String();
              const info = inetConnMap[hConnect.toString()];
              const hostPort = info ? (info.host + (info.port ? (':' + info.port) : '')) : '';
              if (obj.indexOf('register.php') !== -1 || obj.indexOf('login.php') !== -1) {
                console.log('[WinINet HttpOpenRequestW] ' + verb + ' https://' + hostPort + obj);
              }
            } catch (e) {}
          }
        });
        globalThis.__wininet_openreq_hooked = true;
      }
      const HttpSendRequestW = Module.findExportByName('wininet.dll', 'HttpSendRequestW');
      if (HttpSendRequestW && !globalThis.__wininet_send_hooked) {
        Interceptor.attach(HttpSendRequestW, {
          onEnter: function(args) {
            try {
              const headers = args[1].isNull() ? null : args[1].readUtf16String();
              const total = args[3].toInt32 ? args[3].toInt32() : 0;
              if (headers && (headers.indexOf('register.php') !== -1 || headers.indexOf('login.php') !== -1)) {
                console.log('[WinINet HttpSendRequestW headers] ' + headers);
              }
              if (total > 0) console.log('[WinINet HttpSendRequestW] data length: ' + total);
            } catch (e) {}
          }
        });
        globalThis.__wininet_send_hooked = true;
      }
      const InternetOpenUrlW = Module.findExportByName('wininet.dll', 'InternetOpenUrlW');
      if (InternetOpenUrlW && !globalThis.__wininet_openurl_hooked) {
        Interceptor.attach(InternetOpenUrlW, {
          onEnter: function(args) {
            try {
              const url = args[1].isNull() ? '' : args[1].readUtf16String();
              if (url.indexOf('register.php') !== -1 || url.indexOf('login.php') !== -1) {
                console.log('[WinINet InternetOpenUrlW] ' + url);
              }
            } catch (e) {}
          }
        });
        globalThis.__wininet_openurl_hooked = true;
      }

      // Winsock raw send hooks to sniff HTTP requests regardless of stack
      try {
        const ws2 = Process.findModuleByName('ws2_32.dll');
        if (ws2) {
          const sendPtr = Module.findExportByName('ws2_32.dll', 'send');
          if (sendPtr && !globalThis.__send_hooked) {
            Interceptor.attach(sendPtr, {
              onEnter: function(args) {
                try {
                  const buf = args[1];
                  const len = args[2].toInt32 ? args[2].toInt32() : 0;
                  if (!buf.isNull() && len > 0 && len < 65536) {
                    const data = buf.readByteArray(len);
                    const s = bytesToAscii(data);
                    if (s.indexOf('/poker/api/register.php') !== -1 || s.indexOf('login.php') !== -1) {
                      console.log('\n[WSA send] ' + s.substring(0, Math.min(s.length, 2048)) + '\n');
                    }
                  }
                } catch (e) {}
              }
            });
            globalThis.__send_hooked = true;
          }
          const wsaSendPtr = Module.findExportByName('ws2_32.dll', 'WSASend');
          if (wsaSendPtr && !globalThis.__wsasend_hooked) {
            Interceptor.attach(wsaSendPtr, {
              onEnter: function(args) {
                try {
                  const lpBuffers = args[1];
                  const count = args[2].toInt32 ? args[2].toInt32() : 0;
                  for (var i = 0; i < Math.min(count, 4); i++) {
                    const base = lpBuffers.add(i * Process.pointerSize * 2);
                    // struct WSABUF { ULONG len; CHAR* buf; }
                    const len = base.readU32();
                    const pbuf = base.add(Process.pointerSize).readPointer();
                    if (!pbuf.isNull() && len > 0 && len < 65536) {
                      const data = Memory.readByteArray(pbuf, len);
                      const s = bytesToAscii(data);
                      if (s.indexOf('/poker/api/register.php') !== -1 || s.indexOf('login.php') !== -1) {
                        console.log('\n[WSASend] ' + s.substring(0, Math.min(s.length, 2048)) + '\n');
                      }
                    }
                  }
                } catch (e) {}
              }
            });
            globalThis.__wsasend_hooked = true;
          }
        }
      } catch (e) {}
    } catch (e) {}
  }

  // Also hook il2cpp_string_new* to catch string constructions containing register.php/username
  try {
    const ga = Process.findModuleByName('GameAssembly.dll');
    const hookStr = function(sym){
      if (!sym) return;
      Interceptor.attach(sym, {
        onEnter: function(args){
          try {
            // il2cpp_string_new(const char* str)
            // il2cpp_string_new_len(const char* str, int len)
            // il2cpp_string_new_utf16(const Il2CppChar* text, int len)
            var s = null;
            if (this.context && this.returnAddress) {}
            if (sym.toString().indexOf('utf16') !== -1) {
              const len = args[1].toInt32 ? args[1].toInt32() : parseInt(args[1]);
              if (len > 0 && len < 4096) s = args[0].readUtf16String(len);
            } else {
              // read C string (may be non-terminated if using _len; best effort)
              try { s = args[0].readUtf8String(); } catch (e) { s = null; }
            }
            if (s && (s.indexOf('register.php') !== -1 || s.indexOf('/poker/api/register.php') !== -1 || s.indexOf('username=') !== -1)) {
              console.log("[il2cpp_string_new*] " + s);
            }
          } catch (e) {}
        }
      });
    };
    hookStr(Module.findExportByName('GameAssembly.dll', 'il2cpp_string_new'));
    hookStr(Module.findExportByName('GameAssembly.dll', 'il2cpp_string_new_len'));
    hookStr(Module.findExportByName('GameAssembly.dll', 'il2cpp_string_new_utf16'));
  } catch (e) {}

  return true;
}

// Poll for module load
var interval = setInterval(function() {
  if (hookGameAssembly()) {
    clearInterval(interval);
  }
}, 1000);

// Config toggles
var FORCE_REG_ON_LOGIN = false;      // call RegisterEmailAccount when Login is called (one-shot)
var DRY_RUN_BLOCK_NET  = false;      // block outgoing network after logging encoded username/password

console.log("[*] Waiting for GameAssembly.dll...");
