##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'
require 'msf/core/post/windows/extapi'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Windows::ExtAPI

  MSF_MODULES = {
    'KB977165'  => "KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)",
    'KB2305420' => "KB2305420 - Possibly vulnerable to MS10-092 schelevator if Vista, 7, and 2008",
    'KB2592799' => "KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2",
    'KB2778930' => "KB2778930 - Possibly vulnerable to MS13-005 hwnd_broadcast, elevates from Low to Medium integrity",
    'KB2850851' => "KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1",
    'KB2870008' => "KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1"
  }

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Windows Gather Applied Patches",
      'Description'     => %q{
          This module will attempt to enumerate which patches are applied to a windows system
          based on the result of the WMI query: SELECT HotFixID FROM Win32_QuickFixEngineering
        },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          =>
        [
          'zeroSteiner', # Original idea
          'mubix' # Post module
        ],
      'References'      =>
        [
          ['URL', 'http://msdn.microsoft.com/en-us/library/aa394391(v=vs.85).aspx']
        ]
    ))

    register_options(
      [
        OptBool.new('MSFLOCALS', [ true, 'Search for missing patchs for which there is a MSF local module', true]),
        OptString.new('KB',  [ true, 'A comma separated list of KB patches to search for', 'KB2871997, KB2928120'])
      ])
  end

  # The sauce starts here
  def run
    patches = []

    datastore['KB'].split(',').each do |kb|
      patches << kb.strip
    end

    if datastore['MSFLOCALS']
      patches = patches + MSF_MODULES.keys
    end

    extapi_loaded = load_extapi
    if extapi_loaded
      begin
        objects = session.extapi.wmi.query("SELECT HotFixID FROM Win32_QuickFixEngineering")
      rescue RuntimeError
        print_error "Known bug in WMI query, try migrating to another process"
        return
      end
      kb_ids = objects[:values].map { |kb| kb[0] }
      report_info(patches, kb_ids)
    else
      print_error "ExtAPI failed to load"
    end
  end

  def report_info(patches, kb_ids)
    patches.each do |kb|
      if kb_ids.include?(kb)
        print_status("#{kb} applied")
      else
        if MSF_MODULES.include?(kb)
          print_good(MSF_MODULES[kb])
        else
          print_good("#{kb} is missing")
        end
      end
    end
  end
end
