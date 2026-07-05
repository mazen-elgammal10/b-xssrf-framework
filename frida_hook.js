Java.perform(function () {

    console.log("[+] Frida Hook Started");

    // 🔥 Hook HTTP URLs
    var URL = Java.use("java.net.URL");
    URL.$init.overload("java.lang.String").implementation = function (url) {
        console.log("[URL] => " + url);
        return this.$init(url);
    };

    // 🔥 Hook OkHttp (مهم جدًا)
    try {
        var Request = Java.use("okhttp3.Request$Builder");

        Request.url.overload("java.lang.String").implementation = function (url) {
            console.log("[OKHTTP URL] => " + url);
            return this.url(url);
        };

    } catch (e) {}

    // 🔥 Hook Headers (Tokens)
    try {
        var Headers = Java.use("okhttp3.Request$Builder");

        Headers.addHeader.overload("java.lang.String", "java.lang.String")
        .implementation = function (k, v) {
            console.log("[HEADER] " + k + " => " + v);
            return this.addHeader(k, v);
        };

    } catch (e) {}

    // 🔥 Hook SharedPreferences (tokens مخزنة)
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");

    SharedPreferences.getString.overload('java.lang.String', 'java.lang.String')
    .implementation = function (key, def) {
        var value = this.getString(key, def);
        console.log("[PREF] " + key + " => " + value);
        return value;
    };

});
