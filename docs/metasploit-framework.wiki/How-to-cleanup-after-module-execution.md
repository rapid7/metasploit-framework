## On this page

* [Cleanup method](#cleanup-method)
* [FileDropper Mixin](#filedropper-mixin)

## Cleanup method

Metasploit has a handy `cleanup` method that is always called when the module terminates, whether it is successful or not. This method can be overridden by any modules to add their own cleanup routines. For example, this might be useful to put some files back on the target after the module had deleted them. Another scenario would be to restore the settings in a web application that were modified by the exploit. This is the right place to clean things up.

Framework itself implements this method to disconnect connections, call the handler cleanup routines, etc. Some other mixins, such as the `Msf::Exploit::FileDropper` (see the next [section](#filedropper-mixin)) or `Msf::Exploit::Remote::Kerberos::Client`, override this method to add their own cleanup code. It is extremely important to **always** call `super` in your `cleanup` method to make sure Framework and any other mixins clean up themself properly.

Here is an example that restores a configuration file after being deleted by the module:
```ruby
def cleanup
  unless self.conf_content.nil?
    write_file(self.conf_file, self.conf_content)
  end

  super
end
```

Here is another example of a `cleanup` method that deletes a temporary Git repository:
```ruby
def cleanup
  super
  return unless need_cleanup?

  print_status('Cleaning up')
  uri = normalize_uri(datastore['USERNAME'], self.repo_name, '/settings')
  csrf = get_csrf(uri)
  res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI'], uri),
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        _csrf: csrf,
        action: 'delete',
        repo_name: self.repo_name
      }
  })

  unless res
    fail_with(Failure::Unreachable, 'Unable to reach the settings page')
  end

  unless res.code == 302
    fail_with(Failure::UnexpectedReply, 'Delete repository failure')
  end

  print_status("Repository #{self.repo_name} deleted.")

  nil
end
```

## FileDropper Mixin

In some exploitation scenarios such as local privilege escalation, command execution, write privilege attacks, SQL Injections, etc, it is very likely that you have to upload one or more malicious files in order to gain control of the target machine. Well, a smart attacker shouldn't leave anything behind, so if a module needs to drop something onto the file system, it's important to remove it right after the purpose is served. And that is why we created the FileDropper mixin.

The [FileDropper mixin](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/file_dropper.rb) is a file manager that allows you to keep track of files, and then delete them when a session is created. To use it, first include the mixin:

```ruby
include Msf::Exploit::FileDropper
```

Next, tell the FileDropper mixin where the file is going to be after a session is created by using the `register_file_for_cleanup` method. Each file name should either be a full path or relative to the current working directory of the session. For example, if I want to upload a payload to the target machine's remote path: `C:\Windows\System32\payload.exe`, then my statement can be:

```ruby
register_file_for_cleanup("C:\\Windows\\System32\\payload.exe")
```

If my session's current directory is already in `C:\Windows\System32\`, then you can:

```ruby
register_file_for_cleanup("payload.exe")
```

If you wish to register multiple files, you can also provide the file names as arguments:

```ruby
register_file_for_cleanup("file_1.vbs", "file_2.exe", "file_1.conf")
```

Note that if your exploit module uses `on_new_session`, you are actually overriding FileDropper's `on_new_session`.

