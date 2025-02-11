# Background
Not long ago, [this](https://gist.github.com/hackermondev/45a3cdfa52246f1d1201c1e8cdef6117) interesting post was written about the ability to deanonymize people by using Cloudflare's caching mechanism. In short, Cloudflare will cache files at data centers close to where previous requests have occurred to speed up future requests for the same file. By checking whether a file has been cached at specific data centers (which Cloudflare refers to as a colo), we can roughly geolocate where a person is.

The implementation in the post relies on using a Cloudflare Worker to force internal routing through specific data centers as an exit point, allowing the checking of _all_ available locations. This seems to have been patched which preclues that method from working but the core idea of using cache as a mechanism to check the rough location of a user remains valid.

After testing and failing with the Cloudflare Worker, I decided to try another approach. The Worker was essentially re-routing the traffic to exit in a specific location so that it could check the cache in that area. By terminating my own connection in those same locations, I can achieve the same effect.

Doing so with a VPN would be way too slow and setting up a VPS in each of those locations would also be a pain in the ass; so I turned to web proxies. These do essentially the same thing for web requests (which is all that's required) and it's scalable from the point of view of trying to quickly send requests from as many locations as possible. The problem is that finding free proxies in all of those locations is difficult (probably unachievable) but worth a try.

> [!NOTE]
> This post is a bit of a writeup on my methodology. The python script will do the heavy lifting, scroll to the [bottom](https://github.com/Schecken/not-cf-teleport/README.md#proxy-scraper-and-cloudflare-cache-checker) to see usage.

> [!CAUTION]
> The hardest part with this is finding free proxies in every location there is a data center. My script relies in other sources to find proxies and I have not been able to reliably find them in all required locations. If you have other sources for proxies that allows you to check cache in all of those locations, the logic of this should work and you should be successful.

## tl;dr
1. Get a URL for a Signal attachment sent to a target user
2. Find proxies in proximity to all Cloudflare colos
3. Use proxies to check whether Signal attachment had been cached at any of the colos

# Step 1 - Getting a URL to test
In the original post, Signal is used as an example of a use-case. There weren't any notes on how to actually get the URL that Signal wraps in TLS so I figured it out for myself. I had no previous knowledge and had never worked with Android apps before.

A couple of useful articles:

https://petruknisme.medium.com/easy-way-to-bypass-ssl-pinning-with-objection-frida-beginner-friendly-58118be4094 \
https://developer.android.com/studio/run/emulator

After some research, I decided to emulate the phone in Android Studio.

## Install Emulator
### Install Android Studio
```bash
# Follow these instructions
https://developer.android.com/codelabs/basic-android-kotlin-compose-install-android-studio#6

# Download setup files:
https://developer.android.com/studio/?gclid=Cj0KCQiAjJOQBhCkARIsAEKMtO3zEhdK4_I0CEZic3UH4dl-9gVXuHFR9dCl3TOHKjmv3xWLU3UxfhYaApfAEALw_wcB&gclsrc=aw.ds

# Turn on VT-x/SVM
VMWare -> Settings -> Processors -> Enable VT-x or SVM

# Start
android-studio/bin/studio

# Make sure to run an image that isn't marked as Google Play so we can run as root (may have to download another image from the list)
```

### Set up the image
> [!IMPORTANT]
> I don't think I actually needed to use `frida`. I didn't actually check but because I patched the Signal apk, the hooking was irrelevant. I've left the notes in here only because they're useful and might help someone.
```bash
# Download and install required components
pip install frida-tools

wget https://github.com/frida/frida/releases/download/16.6.5/frida-server-16.6.5-android-x86_64.xz
xz -d frida-server-16.6.5-android-x86_64.xz
mv frida-server-16.6.5-android-x86_64 frida-server

# Push server onto device image
adb push frida-server /data/local/tmp
```

### Run the frida server
```bash
adb root
adb shell
su
cd /data/local/tmp/
chmod +x frida-server
./frida-server &

#  Check it's running
ps | grep frida
```

## Configure Proxy
Open Burp Suite and start Proxy on:
```bash
ip -br a
br-24190549bf5f  DOWN           10.168.137.1/24 

IP Address: 10.168.137.1
Port: 8090
```

Set proxy on Android emulator
```
Settings -> Network & Internet -> Internet -> Android Wi-Fi -> Pen (Edit) top right corner -> Proxy -> Manual

Proxy hostname: 10.168.137.1
Proxy port: 8090
Save
```

> [!IMPORTANT]
> Installing the Burp cert didn't work for me, I couldn't import it at all. Kept getting an error because the system wasn't writable but I couldn't change it. Either way, I didn't end up needing it; maybe because I was able to patch the Signal apk

## Patch Signal (SSL Unpinning)
### apk-mitm
https://github.com/niklashigi/apk-mitm
I patched the Signal app using this
```bash
wget https://updates.signal.org/android/Signal-Android-website-prod-universal-release-7.30.2.apk
apk-mitm Signal-Android-website-prod-universal-release-7.30.2.apk
```

### Of interest
This dude has done a few apps already, just not Signal. Worth a look later on if testing the same thing using these other apps.
https://github.com/Eltion/Messenger-SSL-Pinning-Bypass \
https://github.com/Eltion/Facebook-SSL-Pinning-Bypass

## Register Signal
Had to register another phone to the damn Signal app because I couldn't link my existing one...

## Hook and Intecept Traffic
> [!NOTE]
> Not sure if this part is actually required. This will allow you to hook the application before it's wrapped in encryption though.

### Use `frida`
https://www.youtube.com/watch?v=oy0mn5CV-ro
```bash
# Attach to Signal with frida
frida -U Signal

# Find all classes (Signal starts with org.thoughtcrime.securesms)
Java.enumerateLoadedClassesSync();

# Apparently this is the one for HTTPS messaging
"okhttp3.internal.ws.RealWebSocket$Message"

# Hooka and trace Signal with frida
# If you send messages in Signal after hooking, it should show it in the output
frida-trace -U Signal -j 'org.thoughtcrime.securesms*Message*!*' -J '*!*$*'
```

### Use Objection
This allows us to connect to the `frida` server and hook the app
```bash
pip install -U objection

# Check to see if it works
objection --gadget "com.android.settings" device-type
```

After sending an attachment, I could see the requests for `cdn2.signal.org` in the `Logger` tab of Burp. See the response which has the `Cf-Ray` header in it that discloses closest data center

![image](https://github.com/user-attachments/assets/65015b70-dd63-4639-9583-7504d99505fc)

Unencrypted URLs from Signal attachments that can now be used for testing:
```
https://cdn2.signal.org/attachments/SKEb2vm8AJzGxvcuX2JF
https://cdn2.signal.org/attachments/yNmOaLrJNzXTWm8fqXzS
https://cdn2.signal.org/attachments/QAc4nhCbTtZShDHqWGl3
```

# Step 2 & 3 - Find Proxies and Check Cache
Through a bunch of back-and-forth with ChatGPT and testing, I eventually created a script that allows me to scrape a bunch of free proxies, validate that they work, and use them to find the last cache time on Cloudflare colos.

## Proxy scraper and Cloudflare cache checker

This script has two sub-commands:

1. `scrape`
   Gather proxies from various online sources, test them against Cloudflare’s trace endpoint, and save (or update) a JSON file with only the validated proxies. The JSON is grouped by country and data center (colo). It also shows which Cloudflare data centers (colos) are missing at least one working proxy if the option is set.

   Usage examples:
     - Overwrite mode:
         `python3 scraper.py scrape -o validated-proxies.json`
     - Update mode (merge new validated proxies into an existing file):
         `python3 scraper.py scrape -add validated-proxies.json`
     Additional options:
        ` -v`, `--verbose`     : Enable verbose output (debug info).
        ` --show-missing`    : After testing, print a list of missing Cloudflare colos.

2. `check`
   Use a JSON file of validated proxies (generated in scrape mode) to test a given URL (for example, an image URL hosted behind Cloudflare) and determine its cache status. The script makes a request through one proxy per country/data-center group, prints a
   line-by-line result (including the proxy used) and, finally, prints a summary showing for each HIT the time since the cache was created (converted to “X mins Y seconds ago”) along with the full location (city, country).

   Usage example:
         `python3 scraper.py check -i validated-proxies.json -u https://github.githubassets.com/favicons/favicon.png`
   Additional option:
         `-v`, `--verbose` : Enable verbose output.

Run with `-h` or `--help` for more details on each sub-command.

![image](https://github.com/user-attachments/assets/a91f0be2-29cd-49e6-a002-5f8972d4db9b)

**Note:** you can add your own sources in the script, just make sure they are annotated as `text` or `html-ssl` as it will help with parsing. If the parsing doesn't work nicely (particularly if it's a webpage), you might have to create a new function to fix it.
