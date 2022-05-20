## On this page

* [Examples](#examples)
* [Reference](#reference)

In some exploitation scenarios such as local privilege escalation, command execution, write privilege attacks, SQL Injections, etc, it is very likely that you have to upload one or more malicious files in order to gain control of the target machine. Well, a smart attacker shouldn't leave anything behind, so if a module needs to drop something onto the file system, it's important to remove it right after the purpose is served. And that is why we created the FileDropper mixin.

## Examples

The FileDropper mixin is a file manager that allows you to keep track of files, and then delete them when a session is created. To use it, first include the mixin:

```ruby
include Msf::Exploit::FileDropper
```

Next, tell the FileDropper mixin where the file is going to be after a session is created by using the ```register_file_for_cleanup``` method. Each file name should either be a full path or relative to the current working directory of the session. For example, if I want to upload a payload to the target machine's remote path: ```C:\Windows\System32\payload.exe```, then my statement can be:

```ruby
register_file_for_cleanup("C:\\Windows\\System32\\payload.exe")
```

If my session's current directory is already in ```C:\Windows\System32\```, then you can:

```ruby
register_file_for_cleanup("payload.exe")
```

If you wish to register multiple files, you can also provide the file names as arguments:

```ruby
register_file_for_cleanup("file_1.vbs", "file_2.exe", "file_1.conf")
```

Note that if your exploit module uses ```on_new_session```, you are actually overriding FileDropper's ```on_new_session```.

## Reference

- <https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/file_dropper.rb>
