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
LEV_0 | The default log level if none is specified. It should be used when a log message should always be displayed when logging is enabled. Very few log messages should occur at this level aside from necessary information logging and error/warning logging.  Debug logging at level zero is not advised.
