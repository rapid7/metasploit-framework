In Metasploit, exploits and auxiliary modules support the check command that allows the user to be able to determine the vulnerable state before using the module. This feature is handy for those who need to verify the vulnerability without actually popping a shell, and used to quickly identify all vulnerable, or possibly exploitable machines on the network.

Although vulnerability checks aren't the focus of Metasploit, because it isn't a vulnerability scanner like Nexpose, we do actually encourage people to implement the check() method anyway to add more value to the module. If you do write one, make sure to keep these guidelines in mind:

## Check Method Output

Modules messages are important to the user, because they keep the user informed about what the module is doing, and usually make the module more debuggable. However, you do also want to keep your messages in verbose mode because it becomes really noisy if the check is used against multiple targets. Ideally, you only should be using these print methods:

| Method | Description |
| ------ | ----------- |
| **vprint_line()** | verbose version of print_line |
| **vprint_status()** | verbose version of print_status that begins with "[*]" |
| **vprint_error()** | verbose version of print_error that begins with "[x]" |
| **vprint_warning()** | verbose version of print_warning that begins with "[!]", in yellow |

Better yet, use the `CheckCode` description to provide additional information (see below).

Note: You shouldn't be printing if a target is vulnerable or not, as this is automatically handled by the framework when your method returns a check code.


## Check Codes

Once you have determined the vulnerable state, you should return a check code. Check codes are constants defined in `Msf::Exploit::CheckCode`, and these are the ones you can use:

| Checkcode | Description |
| --------- | ----------- |
| **Exploit::CheckCode::Unknown** | Used if the module fails to retrieve enough information from the target machine, such as due to a timeout. |
| **Exploit::CheckCode::Safe** | Used if the check fails to trigger the vulnerability, or even detect the service. |
| **Exploit::CheckCode::Detected** | The target is running the service in question, but the check fails to determine whether the target is vulnerable or not. |
| **Exploit::CheckCode::Appears** | This is used if the vulnerability is determined based on passive reconnaissance. For example: version, banner grabbing, or simply having the resource that's known to be vulnerable. |
| **Exploit::CheckCode::Vulnerable** | Only used if the check is able to actually take advantage of the bug, and obtain some sort of hard evidence. For example: for a command execution type bug, get a command output from the target system. For a directory traversal, read a file from the target, etc. Since this level of check is pretty aggressive in nature, you should not try to DoS the host as a way to prove the vulnerability. |
| **Exploit::CheckCode::Unsupported** | The exploit does not support the check method. If this is the case, then you don't really have to add the check method. |

The `CheckCode` also supports an optional description which is printed by the framework upon completion of the `check` method. For example:

```ruby
return CheckCode::Appears('Vulnerable component XYZ is installed')
```

`MetasploitModule#check` methods should capture any known `raise` from methods called and return value of class
`Msf::Exploit::CheckCode`. Basically, that means avoiding the use of `fail_with` or raising exceptions that are not
handled within the check method.

## Remote Check Example

Here's an abstract example of how a Metasploit check might be written:

```ruby
#
# Returns a check code that indicates the vulnerable state on an app running on OS X
#
def check
  if exec_cmd_via_http("id") =~ /uid=\d+\(.+\)/
    # Found the correct ID output, good indicating our command executed
    return Exploit::CheckCode::Vulnerable
  end

  http_body = get_http_body
  if http_body
    if http_body =~ /Something CMS v1\.0/
      # We are able to find the version thefore more precise about the vuln state
      return Exploit::CheckCode::Appears
    elsif http_body =~ /Something CMS/
      # All we can tell the vulnerable app is running, but no more info to
      # determine the vuln
      return Exploit::CheckCode::Detected
    end
  else
    vprint_error("Unable to determine due to a HTTP connection timeout")
    return Exploit::CheckCode::Unknown
  end

  Exploit::CheckCode::Safe
end
```

Note: If you are writing an auxiliary module with the `Msf::Auxiliary::Scanner` mixin, you should declare your check method like this:

```ruby
def check_host(ip)
  # Do your thing
end
```

### Local Exploit Check Example

Most local exploit checks are done by checking the version of the vulnerable file, which is considered passive, therefore they should be flagging `Exploit::CheckCode::Appears`. Passive local exploit checks don't necessarily mean they are less reliable, in fact, they are not bad. But to qualify for `Exploit::CheckCode::Vulnerable`, your check should do the extra mile, which means either you somehow make the program return a vulnerable response, or you inspect the vulnerable code.

An example of making the program return a vulnerable response is ShellShock (the following is specific for VMWare):

```ruby
def check
  check_str = Rex::Text.rand_text_alphanumeric(5)
  # ensure they are vulnerable to bash env variable bug
  if cmd_exec("env x='() { :;}; echo #{check_str}' bash -c echo").include?(check_str) &&
     cmd_exec("file '#{datastore['VMWARE_PATH']}'") !~ /cannot open/

     Exploit::CheckCode::Vulnerable
  else
    Exploit::CheckCode::Safe
  end
end
```

One way to inspect the vulnerable code is to come up with a signature, and see if it exists in the vulnerable process. Here's an example with adobe_sandbox_adobecollabsync.rb:

```ruby
# 'AdobeCollabSyncTriggerSignature' => "\x56\x68\xBC\x00\x00\x00\xE8\xF5\xFD\xFF\xFF"
# 'AdobeCollabSyncTrigger' => 0x18fa0

def check_trigger
  signature = session.railgun.memread(@addresses['AcroRd32.exe'] + target['AdobeCollabSyncTrigger'], target['AdobeCollabSyncTriggerSignature'].length)
  if signature == target['AdobeCollabSyncTriggerSignature']
    return true
  end

  return false
end

def check
  @addresses = {}
  acrord32 = session.railgun.kernel32.GetModuleHandleA("AcroRd32.exe")
  @addresses['AcroRd32.exe'] = acrord32["return"]
  if @addresses['AcroRd32.exe'] == 0
    return Msf::Exploit::CheckCode::Unknown
  elsif check_trigger
    return Msf::Exploit::CheckCode::Vulnerable
  else
    return Msf::Exploit::CheckCode::Detected
  end
end
```

Another possible way to inspect is grab the vulnerable file, and use Metasm. But of course, this is a lot slower and generates more network traffic.


## AutoCheck Mixin

Metasploit offers the possibility to automatically call the `check` method before the `exploit` or `run` method is run. Just prepend the `AutoCheck` module for this, nothing more:

```ruby
  prepend Msf::Exploit::Remote::AutoCheck
```

According to the `CheckCode` returned by the `check` method, Framework will decided if the module should be executed or not:

| Checkcode | Module executed? |
| --------- | ----------- |
| **Exploit::CheckCode::Vulnerable** | yes |
| **Exploit::CheckCode::Appears** | yes |
| **Exploit::CheckCode::Detected** | yes |
| **Exploit::CheckCode::Safe** | no |
| **Exploit::CheckCode::Unsupported** | no |
| **Exploit::CheckCode::Unknown** | no |

This mixin brings two new options that let the operator control its behavior:
- `AutoCheck`: Sets whether or not the `check` method will be run. Default is `true`.
- `ForceExploit`: Override the check result. The `check` method is run but the module will be executed regardless of the result. Default is `false`.
