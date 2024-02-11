---
layout: post
title: Strings - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Strings](https://www.mobilehackinglab.com/course/lab-strings) lab challenges us to uncover a hidden flag within the application. <!--more--> In this blog post, I'll walk you through my journey to crack this challange. From unraveling cryptic clues to unveiling the final secret, I'll explain each step along the way. Join me as I navigate through the code and reveal the flag.

### Introduction

After downloading the APK of the application, upon opening it, we are greeted with a message saying "Hello from C++." Since we can't do much within the application, we'll proceed to analyze the code statically using JADX.


### Static Analysis

After examining the `MainActivity` class, we find minimal operations; it bassically loads the `challenge` library and defines the `KLOW` function. This function writes the current date to the Shared Preferences, using the key `UUU0133` and the name `DAD4`.

```java
// MainActivtity

package com.mobilehackinglab.challenge;

...
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainActivity.kt */
@Metadata(m24d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\u0018\u0000 \f2\u00020\u0001:\u0001\fB\u0005¢\u0006\u0002\u0010\u0002J\u0006\u0010\u0005\u001a\u00020\u0006J\u0012\u0010\u0007\u001a\u00020\u00062\b\u0010\b\u001a\u0004\u0018\u00010\tH\u0014J\t\u0010\n\u001a\u00020\u000bH\u0086 R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000¨\u0006\r"}, m23d2 = {"Lcom/mobilehackinglab/challenge/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "binding", "Lcom/mobilehackinglab/challenge/databinding/ActivityMainBinding;", "KLOW", "", "onCreate", "savedInstanceState", "Landroid/os/Bundle;", "stringFromJNI", "", "Companion", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes4.dex */
public final class MainActivity extends AppCompatActivity {
    public static final Companion Companion = new Companion(null);
    private ActivityMainBinding binding;

    public final native String stringFromJNI();

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
        activityMainBinding.sampleText.setText(stringFromJNI());
    }

    /* compiled from: MainActivity.kt */
    @Metadata(m24d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002¨\u0006\u0003"}, m23d2 = {"Lcom/mobilehackinglab/challenge/MainActivity$Companion;", "", "()V", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes4.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        System.loadLibrary("challenge");
    }

    public final void KLOW() {
        SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        Intrinsics.checkNotNullExpressionValue(editor, "edit(...)");
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault());
        String cu_d = sdf.format(new Date());
        editor.putString("UUU0133", cu_d);
        editor.apply();
    }
}
```

As the `MainActivity` lacks information leading us to the flag, let's examine the `AndroidManifest.xml`. Within it, we find the `Activity2` class, marked as exported, indicating accessibility from other applications.

```xml
<!--Android Manifest.xml-->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.mobilehackinglab.challenge" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="34"/>
    <permission android:name="com.mobilehackinglab.challenge.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.mobilehackinglab.challenge.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.Strings" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.mobilehackinglab.challenge.Activity2" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="mhl" android:host="labs"/>
            </intent-filter>
        </activity>
        <activity android:name="com.mobilehackinglab.challenge.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.mobilehackinglab.challenge.androidx-startup">
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


We can see that `Activity2` implements the `mhl` scheme, making it possible to open it via the activity manager using the following format: `mhl://labs/payload`. Looking at the source code of this class, we see that it loads a library called `flag` and calls the `getFlag` method. However, when we open the library in Ghidra, we can see that it is heavily obfuscated, and this path doesn't lead us anywhere useful. Therefore, let's continue our static analysis.

In the `onCreate` method of the class, it starts by validating if it was started as an action view. Then, it checks if the content of the key inside the shared preference `DAD4` with the value `UUU0133` is equal to that of the `m26cd()` function, meaning if it has the value of today's date. After performing these two validations, it checks if a URL is being passed and the host is in the format `mhl://labs`. After this validation, it retrieves the last part of the passed URI and tries to decode the base64 passed, meaning it has to be passed in the form of `mhl://labs/<base_64>`, and then the base64 is checked to see if it matches the expected secret from the `decrypt` function. If it is the expected value, functioning as a kind of authentication, then the `flag` library is loaded into memory. So now let's create a Frida script to discover this secret to pass the correct URI.

```java
// Activity2 
package com.mobilehackinglab.challenge;

...
import kotlin.text.Charsets;

/* compiled from: Activity2.kt */
@Metadata(m24d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\b\u0010\u0003\u001a\u00020\u0004H\u0002J\u001e\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\tJ\t\u0010\n\u001a\u00020\u0004H\u0082 J\u0012\u0010\u000b\u001a\u00020\f2\b\u0010\r\u001a\u0004\u0018\u00010\u000eH\u0014¨\u0006\u000f"}, m23d2 = {"Lcom/mobilehackinglab/challenge/Activity2;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "cd", "", "decrypt", "algorithm", "cipherText", "key", "Ljavax/crypto/spec/SecretKeySpec;", "getflag", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes4.dex */
public final class Activity2 extends AppCompatActivity {
    private final native String getflag();

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0893R.layout.activity_2);
        SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
        String u_1 = sharedPreferences.getString("UUU0133", null);
        boolean isActionView = Intrinsics.areEqual(getIntent().getAction(), "android.intent.action.VIEW");
        boolean isU1Matching = Intrinsics.areEqual(u_1, m26cd());
        if (isActionView && isU1Matching) {
            Uri uri = getIntent().getData();
            if (uri != null && Intrinsics.areEqual(uri.getScheme(), "mhl") && Intrinsics.areEqual(uri.getHost(), "labs")) {
                String base64Value = uri.getLastPathSegment();
                byte[] decodedValue = Base64.decode(base64Value, 0);
                if (decodedValue != null) {
                    String ds = new String(decodedValue, Charsets.UTF_8);
                    byte[] bytes = "your_secret_key_1234567890123456".getBytes(Charsets.UTF_8);
                    Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
                    String str = decrypt("AES/CBC/PKCS5Padding", "bqGrDKdQ8zo26HflRsGvVA==", new SecretKeySpec(bytes, "AES"));
                    if (str.equals(ds)) {
                        System.loadLibrary("flag");
                        String s = getflag();
                        Toast.makeText(getApplicationContext(), s, 1).show();
                        return;
                    }
                    finishAffinity();
                    finish();
                    System.exit(0);
                    return;
                }
                finishAffinity();
                finish();
                System.exit(0);
                return;
            }
            finishAffinity();
            finish();
            System.exit(0);
            return;
        }
        finishAffinity();
        finish();
        System.exit(0);
    }

    public final String decrypt(String algorithm, String cipherText, SecretKeySpec key) {
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        Intrinsics.checkNotNullParameter(cipherText, "cipherText");
        Intrinsics.checkNotNullParameter(key, "key");
        Cipher cipher = Cipher.getInstance(algorithm);
        try {
            byte[] bytes = Activity2Kt.fixedIV.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            IvParameterSpec ivSpec = new IvParameterSpec(bytes);
            cipher.init(2, key, ivSpec);
            byte[] decodedCipherText = Base64.decode(cipherText, 0);
            byte[] decrypted = cipher.doFinal(decodedCipherText);
            Intrinsics.checkNotNull(decrypted);
            return new String(decrypted, Charsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    /* renamed from: cd */
    private final String m26cd() {
        String str;
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault());
        String format = sdf.format(new Date());
        Intrinsics.checkNotNullExpressionValue(format, "format(...)");
        Activity2Kt.cu_d = format;
        str = Activity2Kt.cu_d;
        if (str == null) {
            Intrinsics.throwUninitializedPropertyAccessException("cu_d");
            return null;
        }
        return str;
    }
}
```


### Creating the Script

First, we create a script to open `Activity2` using Frida.

```js
//open_activity.js

Java.perform(function () {
   
    setTimeout(function () {
        var Intent = Java.use('android.content.Intent');
            
        // Get the application context
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

        if (context === null) {
            console.error('Failed to get application context. Exiting script.');
            return;
        }
        var Uri = Java.use('android.net.Uri');
        // Create an intent to start the target activity
        var uriString = "mhl://labs/tbf_the_secret_in_base64";
        var uri = Uri.parse(uriString);

        // Create an intent with action android.intent.action.VIEW
        var intent = Intent.$new("android.intent.action.VIEW", uri);
        // Add FLAG_ACTIVITY_NEW_TASK flag
        intent.addFlags(0x10000000); // or Intent.FLAG_ACTIVITY_NEW_TASK

        context.startActivity(intent);
    }, 500);
});
```

Since we don't know the secret yet, let's create another Frida script to hook methods in the `Activity2` class.

```js
//find_secrets.js

Java.perform(function() {
    
    var Intrinsics = Java.use('kotlin.jvm.internal.Intrinsics');

    var Activity2 = Java.use('com.mobilehackinglab.challenge.Activity2');

    //Hook on createMethod
    Activity2.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
        console.log("onCreate called");

        //Set the correct value of UUU0133 -> Need to be today date, Machting cd() function
        var cdValue = this.cd();
        var sharedPreferences = this.getSharedPreferences("DAD4", 0);
        var editor = sharedPreferences.edit();
        editor.putString("UUU0133", cdValue);
        editor.apply();
        sharedPreferences.getString("UUU0133", null);
        var u_1 = sharedPreferences.getString("UUU0133", null);
        console.log("SharedPreference UUU0133:", u_1);
        console.log("Value of cd():", cdValue);
        var isU1Matching = Intrinsics.areEqual(u_1, cdValue);
        console.log("Is u_1 matching cd():", isU1Matching);


        //Check if is pass via action view the intent
        var intent = this.getIntent();
        var action = intent.getAction.call(intent);
        var isActionView = Intrinsics.areEqual(action, "android.intent.action.VIEW")
        console.log("Intent action:", isActionView);

     
        //check the uri Value
        var uri = intent.getData();
        if (uri) {
            console.log("Uri value:", uri.toString());
        } else {
            console.log("Uri is null");
        }
         
         var keyBytes = Java.array('byte', [121, 111, 117, 114, 95, 115, 101, 99, 114, 101, 116, 95, 107, 101, 121, 95, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54]);
         var key = Java.use('javax.crypto.spec.SecretKeySpec').$new(keyBytes, "AES");
         var algorithm = "AES/CBC/PKCS5Padding";
         var cipherText = "bqGrDKdQ8zo26HflRsGvVA==";
         this.decrypt(algorithm, cipherText, key);

        // Return value is not used in onCreate
        this.onCreate(savedInstanceState);
    };


    //Check cd function
    Activity2.cd.implementation = function() {
        console.log("cd() method called");

        // Call the original method
        var result = this.cd();

        // Log the result
        console.log("cd() method returned:", result);

        // Return the result
        return result;
    };

    // Hook into the decrypt method
    Activity2.decrypt.overload('java.lang.String', 'java.lang.String', 'javax.crypto.spec.SecretKeySpec').implementation = function(algorithm, cipherText, key) {
        console.log("decrypt called with algorithm:", algorithm, "cipherText:", cipherText, "key:", key);

        // Call the original method
        var result = this.decrypt(algorithm, cipherText, key);

        // Log the decrypted result
        console.log("Decrypted result:", result);

        return result;
    };

    Activity2.getflag.implementation = function() {
        console.log("getflag() called");
        var result = this.getflag();
        console.log("getflag() returned:", result);
        // Return the result
        return result;
    };
});
```

This script sets the value of the `UUU0133` key correctly and helps find the correct value of the base64 secret. So let's run it with frida to find the base64 value.

```bash
frida -Uf com.mobilehackinglab.challenge -l find_secrets.js -l open_activity.js
```

And we get the following output:
```
cd() method called
cd() method returned: 08/02/2024
SharedPreference UUU0133: 08/02/2024
Value of cd(): 08/02/2024
Is u_1 matching cd(): true
Intent action: true
Uri value: mhl://labs/bWhsX3NlY3JldF8xMzM3
decrypt called with algorithm: AES/CBC/PKCS5Padding cipherText: bqGrDKdQ8zo26HflRsGvVA== key: javax.crypto.spec.SecretKeySpec@106fc
Decrypted result: mhl_secret_1337
cd() method called
cd() method returned: 08/02/2024
decrypt called with algorithm: AES/CBC/PKCS5Padding cipherText: bqGrDKdQ8zo26HflRsGvVA== key: javax.crypto.spec.SecretKeySpec@106fc
Decrypted result: mhl_secret_1337
```

We get the secret: `mhl_secret_1337`. This needs to be passed into base64 in the `open_activity.js` script.

After adjusting the `uriString` parameter to `mhl://labs/bWhsX3NlY3JldF8xMzM3` in the `open_activity.js` script, we rerun the app.

And this time we get this output:
```
cd() method called                                                                         
cd() method returned: 08/02/2024                                                           
SharedPreference UUU0133: 08/02/2024
Value of cd(): 08/02/2024
Is u_1 matching cd(): true
Intent action: true
Uri value: mhl://labs/bWhsX3NlY3JldF8xMzM3
decrypt called with algorithm: AES/CBC/PKCS5Padding cipherText: bqGrDKdQ8zo26HflRsGvVA== key: javax.crypto.spec.SecretKeySpec@106fc
Decrypted result: mhl_secret_1337
cd() method called
cd() method returned: 08/02/2024
decrypt called with algorithm: AES/CBC/PKCS5Padding cipherText: bqGrDKdQ8zo26HflRsGvVA== key: javax.crypto.spec.SecretKeySpec@106fc
Decrypted result: mhl_secret_1337
getflag() called
getflag() returned: Success
```

The `getflag` method is being called, but we still haven't obtained the flag. However, the library is loaded into memory. To find the flag, let's try scanning the memory of our application for a string in the format of our flag: `MHL{...}`.

```js

// ADD this to the find_secrets.js script

//When lib loaded -> check in memory for strings containing flag Format and dump it
setTimeout(function () {
//load library
    const library = Process.getModuleByName("libflag.so")

    // scan module memory for flag format -> MHL{
    const pattern = '4d 48 4c 7b';

    Memory.scan(library.base, library.size, pattern, {
        onMatch(address, size) {
        console.log('Memory.scan() found match at: ', address,
            ' with size ', size);
        },
        onComplete() {
        console.log('Memory.scan() complete');
        }
    });

    const results = Memory.scanSync(library.base, library.size, pattern);
    console.log("Result:" + JSON.stringify(results));
    const flag_addr = results[0].address;
    console.log(hexdump(flag_addr,{length: 100}));

}, 1000);

// Return value is not used in onCreate
this.onCreate(savedInstanceState);
};
```

This script performs a memory scan within the flag library. If it finds a string matching the pattern, it will output the hexdump. Let's run the app again and observe the output of the script.

```
cd() method called                                                                                    
cd() method returned: 08/02/2024                                                                      
SharedPreference UUU0133: 08/02/2024                                                       
Value of cd(): 08/02/2024                                                                  
Is u_1 matching cd(): true                                                                 
Intent action: true                                                                        
Uri value: mhl://labs/bWhsX3NlY3JldF8xMzM3                                                 
decrypt called with algorithm: AES/CBC/PKCS5Padding cipherText: bqGrDKdQ8zo26HflRsGvVA== key: javax.cr
ypto.spec.SecretKeySpec@106fc                                                              
Decrypted result: mhl_secret_1337                                                          
cd() method called                                                                         
cd() method returned: 08/02/2024                                                           
decrypt called with algorithm: AES/CBC/PKCS5Padding cipherText: bqGrDKdQ8zo26HflRsGvVA== key: javax.cr
ypto.spec.SecretKeySpec@106fc                                            
Decrypted result: mhl_secret_1337                           
getflag() called                                                         
getflag() returned: Success                                                   
Toast.makeText() called with message: Success                                              
Result:[{"address":"0x6f9f4e805c","size":4}]                                  
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
6f9f4e805c  4d 48 4c 7b 49 4e 5f 54 48 45 5f 4d 45 4d 4f 52  MHL{IN_THE_MEMOR
6f9f4e806c  59 7d 00 00 00 00 00 00 00 00 00 00 00 00 00 00  Y}..............
6f9f4e807c  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................              
6f9f4e808c  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................              
6f9f4e809c  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................              
6f9f4e80ac  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................              
6f9f4e80bc  00 00 00 00                                      ....                         
Memory.scan() found match at:  0x6f9f4e805c  with size  4                                  
Memory.scan() complete              
```

It works! We successfully retrieved the flag from memory: `MHL{IN_THE_MEMORY}`.


### Conclusion 

This lab offers a comprehensive exploration of Frida scripting, covering everything from analyzing function results to memory scanning for secret retrieval. For a hands-on experience with these concepts, visit the lab at [MobileHackingLab - Strings](https://www.mobilehackinglab.com/course/lab-strings). Embark on a journey of discovery and enhance your skills in mobile security.


### Final Scripts

```js
//open_activity.js
Java.perform(function () {
   
    setTimeout(function () {
        var Intent = Java.use('android.content.Intent');
            
        // Get the application context
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

        if (context === null) {
            console.error('Failed to get application context. Exiting script.');
            return;
        }
        var Uri = Java.use('android.net.Uri');
        // Create an intent to start the target activity
        var uriString = "mhl://labs/bWhsX3NlY3JldF8xMzM3";
        var uri = Uri.parse(uriString);

        // Create an intent with action android.intent.action.VIEW
        var intent = Intent.$new("android.intent.action.VIEW", uri);
        // Add FLAG_ACTIVITY_NEW_TASK flag
        intent.addFlags(0x10000000); // or Intent.FLAG_ACTIVITY_NEW_TASK

        context.startActivity(intent);
    }, 500);
});
```

```js
//find_secrets.js
Java.perform(function() {
    
    var Intrinsics = Java.use('kotlin.jvm.internal.Intrinsics');

    var Activity2 = Java.use('com.mobilehackinglab.challenge.Activity2');

    //Hook on createMethod
    Activity2.onCreate.overload('android.os.Bundle').implementation = function(savedInstanceState) {
        console.log("onCreate called");

        //Set the correct value of UUU0133 -> Need to be today date, Machting cd() function
        var cdValue = this.cd();
        var sharedPreferences = this.getSharedPreferences("DAD4", 0);
        var editor = sharedPreferences.edit();
        editor.putString("UUU0133", cdValue);
        editor.apply();
        sharedPreferences.getString("UUU0133", null);
        var u_1 = sharedPreferences.getString("UUU0133", null);
        console.log("SharedPreference UUU0133:", u_1);
        console.log("Value of cd():", cdValue);
        var isU1Matching = Intrinsics.areEqual(u_1, cdValue);
        console.log("Is u_1 matching cd():", isU1Matching);


        //Check if is pass via action view the intent
        var intent = this.getIntent();
        var action = intent.getAction.call(intent);
        var isActionView = Intrinsics.areEqual(action, "android.intent.action.VIEW")
        console.log("Intent action:", isActionView);

     
        //check the uri Value
        var uri = intent.getData();
        if (uri) {
            console.log("Uri value:", uri.toString());
        } else {
            console.log("Uri is null");
        }
         
        //Found the encryped value -> mhl_secret_1337, but it need to be passed as base64 -> bWhsX3NlY3JldF8xMzM3
         var keyBytes = Java.array('byte', [121, 111, 117, 114, 95, 115, 101, 99, 114, 101, 116, 95, 107, 101, 121, 95, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54]);
         var key = Java.use('javax.crypto.spec.SecretKeySpec').$new(keyBytes, "AES");
         var algorithm = "AES/CBC/PKCS5Padding";
         var cipherText = "bqGrDKdQ8zo26HflRsGvVA==";
         this.decrypt(algorithm, cipherText, key);


         //When lib loaded -> check in memory for strings containing flag Format and dump it
         setTimeout(function () {
            //load library
            const library = Process.getModuleByName("libflag.so")
    
            // scan module memory for flag format -> MHL{
            const pattern = '4d 48 4c 7b';
      
            Memory.scan(library.base, library.size, pattern, {
              onMatch(address, size) {
                console.log('Memory.scan() found match at: ', address,
                    ' with size ', size);
              },
              onComplete() {
                console.log('Memory.scan() complete');
              }
            });
            
            const results = Memory.scanSync(library.base, library.size, pattern);
            console.log("Result:" + JSON.stringify(results));
            const flag_addr = results[0].address;
            console.log(hexdump(flag_addr,{length: 100}));
      
          }, 1000);

        // Return value is not used in onCreate
        this.onCreate(savedInstanceState);
    };


    //Check cd function
    Activity2.cd.implementation = function() {
        console.log("cd() method called");

        // Call the original method
        var result = this.cd();

        // Log the result
        console.log("cd() method returned:", result);

        // Return the result
        return result;
    };

    // Hook into the decrypt method
    Activity2.decrypt.overload('java.lang.String', 'java.lang.String', 'javax.crypto.spec.SecretKeySpec').implementation = function(algorithm, cipherText, key) {
        console.log("decrypt called with algorithm:", algorithm, "cipherText:", cipherText, "key:", key);

        // Call the original method
        var result = this.decrypt(algorithm, cipherText, key);

        // Log the decrypted result
        console.log("Decrypted result:", result);

        return result;
    };

    Activity2.getflag.implementation = function() {
        console.log("getflag() called");
        var result = this.getflag();
        console.log("getflag() returned:", result);
        // Return the result
        return result;
    };

    var Toast = Java.use('android.widget.Toast');
    // Hook into the makeText method
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function(context, text, duration) {
       console.log("Toast.makeText() called with message:", text.toString());
       
       // Call the original method
       var result = this.makeText(context, text, duration);
       
       // Return the Toast object
       return result;
   };
});
```