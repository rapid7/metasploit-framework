Browser Autopwn 2 is a complete redesign from the first one, so quite a few things will look and
feel different for you. Here are the features you should know about before using.

## Vulnerable Applications

Browser Autopwn 2 is capable of targeting popular browsers and 3rd party plugins, such as:

* Internet Explorer
* Mozilla Firefox
* Adobe Flash
* Java
* ActiveX
* Silverlight

## Exploit URLs

Normally, the only URL you need to care about is the **BrowserAutoPwn URL**. This is the URL
you should send to the targets you wish to attack.

For debugging purposes, you can also see each browser exploit's specific URL path. You can do so
by setting the VERBOSE option to true in msfconsole, like this:

```
set VERBOSE true
```

And then when you run the module, there will be a list showing all the exploits that might be
used, including the URLs.

## Browser Autopwn 2 Options

**The HTMLContent Option**

The HTMLContent option allows you to serve a basic HTML web page to the browser instead of having a
blank one. It supports two syntaxes.

This example will basically print "Hello world!" on the browser while exploits are tested against
it.

```
set HTMLContent Hello world!  
```

This example will load file /tmp/hello_world.html and that's what the browser will see. Most likely
the second syntax is how you'd want to use the Content option.

Keep in mind that you should probably try to keep HTMLContent as simple as possible, otherwise
there is a possibility that it might actually influence the reliability of the exploits, especially
the ones that do memory corruption.

**The EXCLUDE_PATTERN option**

The EXCLUDE_PATTERN option is used for excluding exploit file names you don't want Browser
Autopwn 2 to use. This is a regex type option, you can be creative about this.

For example, Adobe Flash exploits in Metasploit tend to have the same file name that begins with:
"adobe_flash_", so to exclude those, you can do:

```
set EXCLUDE_PATTERN adobe_flash  
```

**The INCLUDE_PATTERN option**

The INCLUDE_PATTERN option is for loading specific exploits that you want Browser Autopwn 2 to use.
Let's reuse the Adobe Flash file name example, if you only want Flash exploits, you can do:

```
set INCLUDE_PATTERN adobe_flash  
```

If you set both INCLUDE_PATTERN and EXCLUDE_PATTERN, the evaluation for INCLUDE_PATTERN will kick
in first, followed by EXCLUDE_PATTERN.

**The MaxExploitCount option**

The MaxExploitCount option is for specifying how many exploits you want Browser Autopwn 2 to load.
By default, it's 21. But you can try to bump it up a little bit if you wish to try more exploits.
Note that by doing so you are also allowing more lower ranking modules to kick in, you will have
to figure out the sweet spot for it. An example of setting it:

```
set MaxExploitCount 30 
```

**The MaxSessionCount option**

The MaxSessionCount option is for limiting how many sessions to get. It may sound a little odd at
first because why would you want to do that, right? Well, a use case for this is when you don't
actually want to pop shells, instead you just want to know what exploits could be used, this is
something you can try. You can also use this if you don't want your attack to stay open the whole
time:

```
set MaxSessionCount 10  
```

**The ShowExploitList option**

The ShowExploitList option means displaying a list of exploits specific to each browser/client.
As we've explained before, when BAP2 loads 21 exploits, probably not all 21 will be served to
the browser, only some of them. In order to see those ones, you need to set this option:

```
set ShowExploitList true
```

**The AllowedAddresses option**

The AllowedAddresses option is for attacking a specific range of IPs as a way to avoid penetration
testing accidents. For example, when you send a malicious link to a specific person, that person
may actually share it with his friends, family or other people, and those people aren't your
targets so you shouldn't hit them. Well, Browser Autopwn doesn't know that, so one of the ways to
avoid that is to create a whitelist.
 
The option also supports two syntaxes. This is most likely how you will set it:

```
set AllowedAddresses file:///tmp/ip_list.txt  
```

The above will load file ip_list.txt. In that file, one IP per line.


**The ExploitReloadTimeout option**

The ExploitReloadTimeout is for setting how long BAP2 should wait before loading the next exploit.
By default, it's 3 seconds, but in case some exploits need more time (for example, longer time to
groom the heap, load other things, or it's doing a sleep somewhere), you will need to set this.
In most cases, you shouldn't have to.
 
Here's an example of setting it to 5 seconds:

```
set ExploitReloadTimeout 5000
```

## Scenarios

By default, Browser Autopwn 2 goes through the entire exploit module tree, and will try to use
different types of exploits - Firefox, Internet Explorer, Adobe Flash, Android, etc. If you want to
test a specific application, basically all you need to do is setting the
INCLUDE_PATTERN option (or maybe EXCLUDE_PATTERN).
 
However, there is another trick to make this task even easier. BAP2 also comes with the following
resource scripts that can automatically do this:

* bap_firefox_only.rc - For testing Firefox
* bap_flash_only.rc - Fore testing Adobe Flash
* bap_ie_only.rc - For testing Internet Explorer
* bap_dryrun_only.rc - Rickrolls the target, and shows you all the suitable exploits against that target. No exploits will actually be fired.

Here's an example of using bap_flash_only.rc to test Adobe Flash vulnerabilities:

```
$ ./msfconsole -q -r scripts/resource/bap_flash_only.rc   
```

## Logging

In addition, when a browser connects to BAP, this link-clicking event is also logged to the
database as a "bap.clicks" note type. If the ShowExploitList option is set to true, that will also
save the exploit list information so that after testing you can go back to the database and see
which users are vulnerable to what exploits.

Even if you don't set the ShowExploitList option, the logged link-clicking event data is more than
enough to prove that the user was social-engineered, which is still a security risk.

To see all the bap.clicks events, in msfconsole do:

```
notes -t bap.clicks
```

From there, you can do additional analysis of these notes, put it on your report, and hopefully
do something about it.
