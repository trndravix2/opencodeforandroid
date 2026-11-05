# Dravix release hardening rules
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,JavascriptInterface

# Exposed to the WebView by name (window.DravixNative).
-keep class com.dravix.ai.DravixBridge { *; }
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Apache Commons Compress optional codecs (not bundled).
-dontwarn org.apache.commons.compress.**
-dontwarn org.tukaani.xz.**
-dontwarn com.github.luben.zstd.**
-dontwarn org.brotli.**
