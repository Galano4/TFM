Java.perform(function () {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkTrustedRecursive.implementation = function() {
        return Java.use("java.util.ArrayList").$new();
    };
    console.log("[*] Universal SSL Pinning Bypass applied");
});
