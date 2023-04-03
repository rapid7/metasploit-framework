Metasploit has a handy `cleanup` method that is always called when the module terminates, whether it is successful or not. This method can be overridden by any modules to add their own cleanup routines. For example, this might be useful to put some files back on the target after the module had deleted them. Another scenario would be to restore the settings in a web application that were modified by the exploit. This is the right place to clean things up.

Framework itself implements this method to disconnect connections, call the handler cleanup routines, etc. Some other mixins, such as the `Msf::Exploit::FileDropper` or `Msf::Exploit::Remote::Kerberos::Client`, override this method to add their own cleanup code. It is extremely important to **always** call `super` in your `cleanup` method to make sure Framework and any other mixins clean up themself properly.

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
  res = http_post_request(uri, action: 'delete', repo_name: self.repo_name)

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


