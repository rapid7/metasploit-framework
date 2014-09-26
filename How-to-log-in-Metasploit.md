Usually, if a Metasploit triggers an error, there is a backtrace or at least a brief message that explains what the problem is about. Most of the time, there is nothing wrong with that. But sometimes if you wish to report that problem, you might lose that information, which makes your bug report less informative, and the problem may take much longer to solve.

As an user, you should know that all the logged errors are saved in a file named **framework.log**. The save path is defined in Msf::Config.log_directory, which means in msfconsole, you can switch to irb and figure out where it is:

```
msf > irb
[*] Starting IRB shell...

>> Msf::Config.log_directory
=> "/Users/test/.msf4/logs"
```

By default, msfconsole logs errors on level 0 - the least informative level. But of course, you can change this by setting the datastore option, like this:


```
msf > setg LogLevel 3
LogLevel => 3
msf >
```

There are 4 different logging levels defined in [log/rex/constants.rb](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/constants.rb):

Log Level | Description
--------- | -----------
LEV_0 (Default) | The default log level if none is specified. It should be used when a log message should always be displayed when logging is enabled. Very few log messages should occur at this level aside from necessary information logging and error/warning logging.  Debug logging at level zero is not advised.
LEV_1 (Extra) | This log level should be used when extra information may be needed to understand the cause of an error or warning message or to get debugging information that might give clues as to why something is happening. This log level should be used only when information may be useful to understanding the behavior of something at a basic level.  This log level should not be used in an exhaustively verbose fashion.
LEV_2 (Verbose) | This log level should be used when verbose information may be needed to analyze the behavior of the framework.  This should be the default log level for all detailed information not falling into LEV_0 or LEV_1. It is recommended that this log level be used by default if you are unsure.
LEV_3 (Insanity) | This log level should contain very verbose information about the behavior of the framework, such as detailed information about variable states at certain phases including, but not limited to, loop iterations, function calls, and so on.  This log level will rarely be displayed, but when it is the information provided should make it easy to analyze any problem.
