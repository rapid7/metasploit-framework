**Example**

The presence of `Stability`, `Reliability` and `SideEffects` in the notes section of the info hash is mandatory but may be left empty if it's not applicable to that particular module

Here's an example of what that should look like:
```ruby
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Module name',
        'Description' => %q{
          Module description
        },
        'Author' =>
          [
            'Author name'
          ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            ['CVE', '2020-XXXX']
          ],
        'DisclosureDate' => '2020-03-26',
        'Platform' => 'ruby',
        'Arch' => ARCH_RUBY,
        'Privileged' => false,
        'Targets' => [['Automatic', {}]],
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [...],
          'Reliability' => [...],
          'SideEffects' => [...]
        }
      )
    )
  end
```


**Stability**

| Constant         | Description    |
| -------------- | ------------- |
| CRASH_SAFE  | Module should not crash the service or OS |
| CRASH_SERVICE_RESTARTS | Module may crash the service, but it will restart |
| CRASH_SERVICE_DOWN | Module may crash the service, and remain down |
| CRASH_OS_RESTARTS | Module may crash the OS, but it will restart |
| CRASH_OS_DOWN | Module may crash the OS, and remain down |
| SERVICE_RESOURCE_LOSS | Module causes a resource to be unavailable for the service |
| OS_RESOURCE_LOSS | Module causes a resource to be unavailable for the OS |

**Side Effects**

| Constant         | Description    |
| -------------- | ------------- |
| ARTIFACTS_ON_DISK | Module leaves a payload, a dropper, etc, on the target machine |
| CONFIG_CHANGES | Module modifies some config file |
| IOC_IN_LOGS | Module leaves an indicator of compromise in the log(s) |
| ACCOUNT_LOCKOUTS | Module may cause an account to lock out |
| SCREEN_EFFECTS | Module shows something on the screen that a human may notice |
| PHYSICAL_EFFECTS | Module may produce physical effects in hardware (Examples: light, sound, or heat) |
| AUDIO_EFFECTS | Module may cause a noise (Examples: Audio output from the speakers or hardware beeps) |

**Reliability**

| Constant         | Description    |
| -------------- | ------------- |
| FIRST_ATTEMPT_FAIL | The module may fail for the first attempt |
| REPEATABLE_SESSION | The module is expected to get a session every time it runs |
| UNRELIABLE_SESSION | The module isn't expected to get a shell reliably (such as only once) |

