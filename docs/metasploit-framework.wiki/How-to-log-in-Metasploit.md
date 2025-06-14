Usually, if something in Metasploit triggers an error, there is a backtrace or at least a brief message that explains what the problem is about. Most of the time, there is nothing wrong with that. But sometimes if you wish to report that problem, you might lose that information, which makes your bug report less informative, and the problem may take much longer to solve. This is why logging to file in many cases is extremely useful. In this documentation, we'll explain about how to take advantage of this properly.

## Basic Usage

As an user, you should know that all the logged errors are saved in a file named **framework.log**. The save path is defined in Msf::Config.log_directory, which means in msfconsole, you can switch to irb and figure out where it is:

```
msf > irb
[*] Starting IRB shell...

>> Msf::Config.log_directory
=> "/Users/test/.msf4/logs"
```

By default, all the log errors are on level 0 - the least informative level. But of course, you can change this by setting the datastore option, like this:


```msf
msf > setg LogLevel 3
LogLevel => 3
msf >
```

## Log Levels

There are 4 different logging levels defined in [log/rex/logging.rb](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/logging.rb):

Log Level | Description
--------- | -----------
LEV_0 (Default) | The default log level if none is specified. It should be used when a log message should always be displayed when logging is enabled. Very few log messages should occur at this level aside from necessary information logging and error/warning logging.  Debug logging at level zero is not advised.
LEV_1 (Extra) | This log level should be used when extra information may be needed to understand the cause of an error or warning message or to get debugging information that might give clues as to why something is happening. This log level should be used only when information may be useful to understanding the behavior of something at a basic level.  This log level should not be used in an exhaustively verbose fashion.
LEV_2 (Verbose) | This log level should be used when verbose information may be needed to analyze the behavior of the framework.  This should be the default log level for all detailed information not falling into LEV_0 or LEV_1. It is recommended that this log level be used by default if you are unsure.
LEV_3 (Insanity) | This log level should contain very verbose information about the behavior of the framework, such as detailed information about variable states at certain phases including, but not limited to, loop iterations, function calls, and so on.  This log level will rarely be displayed, but when it is the information provided should make it easy to analyze any problem.

For debugging purposes, it's always better to turn on the highest level of logging.

## Logging API

There are mainly five logging methods you will most likely be using a lot, and they all have the exact same arguments. Let's use one of the logging methods to explain what these arguments are about:

```ruby
def elog(msg, src = 'core', level = 0, from = caller)
```

* msg - The message you want to log
* src - The source of the error (default is core, as in Metasploit core)
* level - The log level
* from - The current execution stack. caller is a method from [Kernel](http://www.ruby-doc.org/core-2.1.3/Kernel.html#method-i-caller).

Notice that only the ```msg``` argument is required, the rest are optional.

Now, let's go over these five methods and explain how they're meant to be used:

Method | Purpose
------ | -------
dlog() | LOG_DEBUG
elog() | LOG_ERROR
wlog() | LOG_WARN
ilog() | LOG_INFO
rlog() | LOG_RAW

## Code Example

```ruby
elog("The sky has fallen")
```
