# Module Examples for AI Agents

These source skeletons illustrate the shared instructions in [AGENTS.md](../AGENTS.md).
They contain placeholders; use the module generator and resolve all placeholders
before submitting. Base classes, mixins, ranks, platforms, architectures, and
session types are illustrative; choose values supported by the actual module.
CodeRabbit applies this reference to exploit, auxiliary, and post module reviews
through `.coderabbit.yaml`. Payloads, encoders, evasion, and nops follow their own
structures; do not require these skeletons or their literal defaults for them.

### Exploit Module Template

New exploit modules should follow this canonical structure and ordering:

```ruby
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  # 1. Protocol mixins first
  include Msf::Exploit::Remote::HttpClient
  # 2. Utility/feature mixins second
  include Msf::Exploit::FileDropper
  # 3. Reporting mixins (if needed)
  # include Msf::Auxiliary::Report
  # 4. AutoCheck ALWAYS LAST — must be prepend, not include
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Vendor Product Vulnerability Type',
        'Description' => %q{
          Description of the vulnerability and what this module does.
        },
        'Author' => [
          'Discoverer Name', # Vulnerability discovery
          'Module Author'    # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-XXXXX'],
          ['URL', 'https://example.com/advisory']
        ],
        'Targets' => [
          [
            'Automatic',
            {
              'Platform' => ['linux'], # or 'win', 'osx', 'unix', 'php', 'python', 'java'
              'Arch' => [ARCH_CMD], # or ARCH_X86, ARCH_X64, ARCH_PHP, ARCH_JAVA, ARCH_PYTHON, ARCH_ARMLE, ARCH_AARCH64, ARCH_MIPSLE — see rex-arch gem for full list
              'Type' => :cmd # or :dropper, :psh_stager — determines payload delivery
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2024-01-01',
        'Notes' => {
          'Stability' => [], # e.g. CRASH_SAFE, CRASH_SERVICE_RESTARTS
          'SideEffects' => [], # e.g. IOC_IN_LOGS, ARTIFACTS_ON_DISK
          'Reliability' => [] # e.g. REPEATABLE_SESSION
        }
      )
    )
  end

  def check
    # Always return CheckCode with a reason string
    CheckCode::Safe('Target is not vulnerable')
  end

  def exploit
    # Exploitation logic
  end
end
```

### Auxiliary Module Template

Auxiliary modules use `def run` (not `exploit`) and inherit from `Msf::Auxiliary`:

```ruby
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Vendor Product Scanner/Gatherer',
        'Description' => %q{
          Description of what this module discovers or does.
        },
        'Author' => ['Author Name'], # Metasploit module
        'License' => MSF_LICENSE,
        'References' => [['CVE', '2024-XXXXX']],
        'Notes' => {
          'Stability' => [], # e.g. CRASH_SAFE
          'SideEffects' => [], # e.g. IOC_IN_LOGS
          'Reliability' => [] # e.g. REPEATABLE_SESSION
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  def check
    Exploit::CheckCode::Safe('Target is not affected')
  end

  def run
    # Main logic — use report_service, report_vuln, print_good, etc.
  end
end
```

### Post Module Template

Post modules inherit from `Msf::Post`, require a session, and declare compatible session types:

```ruby
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Platform Subsystem Gather/Action',
        'Description' => %q{
          Description of what this post module does on the target.
        },
        'Author' => ['Author Name'], # Metasploit module
        'License' => MSF_LICENSE,
        'Platform' => ['linux'], # or 'win', 'osx', 'unix', 'bsd', 'solaris'
        'SessionTypes' => ['meterpreter', 'shell'], # or just ['meterpreter'] if shell won't work
        'Notes' => {
          'Stability' => [], # e.g. CRASH_SAFE
          'SideEffects' => [], # e.g. ARTIFACTS_ON_DISK, CONFIG_CHANGES
          'Reliability' => []
        }
      )
    )
  end

  def run
    # Use create_process, file_exist?, read_file, etc.
    # Access session via `session` method
  end
end
```
