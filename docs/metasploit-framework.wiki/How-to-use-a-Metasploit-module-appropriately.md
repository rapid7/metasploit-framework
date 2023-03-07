As an user, one thing we love Metasploit the most is it allows something really technically difficult to understand or engineer into something really easy to use, literally within a few clicks away to make you look like [Neo](http://en.wikipedia.org/wiki/Neo_(The_Matrix)) from the Matrix. It makes hacking super easy. However, if you're new to Metasploit, know this: [Nobody makes their first jump](https://www.youtube.com/watch?v=3vlzKaH4mpw). You are expected to make mistakes, sometimes small, sometimes catastrophic... hopefully not. You're very likely to fall on your face with your first exploit, just like Neo. Obviously, to become The One you must learn to use these modules appropriately, and we will teach you how.

In this documentation, understand that we require you no exploit development knowledge. Some programming knowledge would be nice, of course. The whole point is that there is actually "homework" before using an exploit, and you should always do your homework.

## Loading a Metasploit module

Each Metasploit module comes with some metadata that explains what it's about, and to see that you must load it first. An example:

```msf
msf > use exploit/windows/smb/ms08_067_netapi
```

## Read the module description and references

This may sound surprising, but sometimes we get asked questions that are already explained in the module. You should always look for the following in the description or the references it provides before deciding whether it's appropriate to use the exploit or not:

* **What products and versions are vulnerable**: This is the most basic thing you should know about a vulnerability.

* **What type of vulnerability and how it works**: Basically, you are learning the exploit's side-effects. For example, if you're exploiting a memory corruption, if it fails due to whatever reason, you may crash the service. Even if it doesn't, when you're done with the shell and type "exit", it's still possible to crash it too. High level bugs are generally safer, but not 100%. For example, maybe it needs to modify a config file or install something that can cause the application to be broken, and may become permanent.

* **Which ones have been tested**: When a module is developed, usually the exploit isn't tested against every single setup if there are too many. Usually the developers will just try to test whatever they can get their hands on. So if your target isn't mentioned here, keep in mind there is no guarantee it's going to work 100%. The safest thing to do is to actually recreate the environment your target has, and test the exploit before hitting the real thing.

* **What conditions the server must meet in order to be exploitable**: Quite often, a vulnerability requires multiple conditions to be exploitable. In some cases you can rely on the exploit's [[check command|How-to-write-a-check-method.md]], because when Metasploit flags something as vulnerable, it actually exploited the bug. For browser exploits using the BrowserExploitServer mixin, it will also check exploitable requirements before loading the exploit. But automation isn't always there, so you should try to find this information before running that "exploit" command. Sometimes it's just common sense, really. For example: a web application's file upload feature might be abused to upload a web-based backdoor, and stuff like that usually requires the upload folder to be accessible for the user. If your target doesn't meet the requirement(s), there is no point to try.

You can use the info command to see the module's description:

```msf
msf exploit(ms08_067_netapi) > info
```

## Read the target list

Every Metasploit exploit has a target list. Basically this is a list of setups the developers have tested before making the exploit publicly available. If your target machine isn't on the list, it's better to assume the exploit has never been tested on that particular setup.

If the exploit supports automatic targeting, it is always the first item on the list (or index 0). The first item is also almost always the default target. What this means is that you should never assume the exploit will automatically select a target for you if you've never used it before, and that the default setup might not be the one you're testing against.

The "show options" command will tell you which target is selected. For example:

```msf
msf exploit(ms08_067_netapi) > show options
```

The "show targets" command will give you a list of targets supported:

```msf
msf exploit(ms08_067_netapi) > show targets
```

## Check all the options

All Metasploit modules come with most datastore options pre-configured. However, they may not be suitable for the particular setup you're testing. To do a quick double-check, usually the "show options" command is enough:

```msf
msf exploit(ms08_067_netapi) > show options
```

However, "show options" only shows you all the basic options. It does not show you the evasive or advanced options (try "show evasion" and "show advanced"), the command you should use that shows you all the datastore options is actually the "set" command:

```msf
msf exploit(ms08_067_netapi) > set
```

## Find the module's pull request

The Metasploit repository is hosted on GitHub, and the developers/contributors rely on it heavily for development. Before a module is made public, it is submitted as a [pull request](https://help.github.com/articles/using-pull-requests/) for final testing and review. In there, you will find pretty much everything you need to know about the module, and probably things you won't learn from reading the module's description or some random blog post. The information is like gold, really.

Things you might learn from reading a pull request:

* Steps on how to set up the vulnerable environment.
* What targets were actually tested.
* How the module is meant to be used.
* How the module was verified.
* What problems were identified. Problems you might want to know.
* Demonstrations.
* Other surprises.

There are a few ways to find the pull request of the module you're using:

* **Via `info -d` in msfconsole**: If you generate a [personal access token](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token) and set it in your shell environment with `export GITHUB_OAUTH_TOKEN your_token`, the builtin documentation will show relevant pull requests for the current module.

* **Via the pull request number**: If you actually know the pull request number, this is the easiest. Simply go:

```
https://github.com/rapid7/metasploit-framework/pull/[PULL REQUEST NUMBER HERE]
```

* **Via filters**: This is most likely how you find the pull request. First off, you should go here: [https://github.com/rapid7/metasploit-framework/pulls](https://github.com/rapid7/metasploit-framework/pulls). At the top, you will see a search input box with the default filters: ```is:pr is:open```. These default ones mean you're looking at pull requests, and you're looking at the ones that are still pending - still waiting to be merged to Metasploit. Well, since you're finding the one that's already merged, you should do these:

1. Click on "Closed".
2. Select label "module".
3. In the search box, enter additional keywords related to the module. The module's title probably provides the best keywords.

Note: If the module was written before Nov 2011, you WILL NOT find the pull request for it.
