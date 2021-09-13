##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::ExtAPI

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => "Windows Gather Applied Patches",
        'Description' => %q{
          This module will attempt to enumerate which patches are applied to a windows system
          based on the result of the WMI query: SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => [
          'zeroSteiner', # Original idea
          'mubix' # Post module
        ],
        'References' => [
          ['URL', 'http://msdn.microsoft.com/en-us/library/aa394391(v=vs.85).aspx']
        ]
      )
    )
  end

  def run
    unless load_extapi
      print_error 'ExtAPI failed to load'
      return
    end

    begin
      objects = session.extapi.wmi.query("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering")
    rescue RuntimeError
      print_error 'Known bug in WMI query, try migrating to another process'
      return
    end

    if objects[:values].nil?
      kb_ids = []
    else
      kb_ids = objects[:values].reject(&:nil?).map { |kb| kb }
    end

    if kb_ids.empty?
      print_status 'Found no patches installed'
      return
    end

    l = store_loot('enum_patches', 'text/plain', session, kb_ids.join("\n"))
    print_status("Patch list saved to #{l}")

    kb_ids.each do |kb|
      print_good("#{kb[0]} installed on #{kb[1]}")
    end
  end
end
