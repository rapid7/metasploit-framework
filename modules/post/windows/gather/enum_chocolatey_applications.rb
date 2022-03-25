##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell

  def initialize(info = {})
    super(update_info(info,
                      "Name" => "Windows Gather Installed Application Within Chocolatey Enumeration",
                      "Description" => %q{ This module will enumerate all installed applications on a Windows system with chocolatey installed },
                      "License" => MSF_LICENSE,
                      "Author" => ["Nick Cottrell <ncottrellweb@gmail.com>"],
                      "Platform" => ["win"],
                      "SessionTypes" => ["meterpreter", "shell"]))
  end

  def have_chocolatey?
    cmd_exec("choco.exe", "-v") =~ /\d+\.\d+\.\d+/m
  end

  def run
    # checking that session is meterpreter and session has powershell
    return 0 if !(have_powershell? || have_chocolatey?)
    if session.type == "meterpreter"
      print_status("Enumerating applications installed on #{sysinfo["Computer"]}")
    end

    # getting chocolatey version
    choco_version = cmd_exec("choco", "-v")
    print_status("Targets Chocolatey version: #{choco_version}")

    # Getting results of listing chocolatey applications
    print_status("Getting chocolatey applications.")

    # checking if chocolatey is 2+ or 1.0.0
    if choco_version.match(/^1\.\d+\.\d+$/)
      # its version 1, use local only
      data = cmd_exec("choco", "list -lo")
    else
      # its version 2 or above, no need for local
      data = cmd_exec("choco", "list")
    end
    print_good("Successfully grabbed all items")

    # making table to better organize applications and their versions
    table = Rex::Text::Table.new(
      "Header" => "Installed Chocolatey Applications",
      "Indent" => 1,
      "Columns" => [
        "Name",
        "Version",
      ],
    )

    # collecting all lines that match and placing them into table.
    items = data.scan(/(\S+)\s(\d+(?:\.\d+)*)/m)
    items.each do |set|
      table << set
    end
    results = table.to_s

    # giving results
    print_line("#{results}")
    p = store_loot("host.applications", "text/plain", session, results, "chocolatey_applications.txt", "Applications Installed with Chocolatey")
    print_good("Results stored in: #{p}")
  end
end
