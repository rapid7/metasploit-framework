##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'VMWare Enumerate Virtual Machines',
            'Description'    => %Q{
              This module attempts to discover virtual machines on any VMWare instance
              running the web interface. This would include ESX/ESXi and VMWare Server.
            },
            'Author'         => ['theLightCosine'],
            'License'        => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, "The username to Authenticate with.", 'root' ]),
        OptString.new('PASSWORD', [ true, "The password to Authenticate with.", 'password' ]),
        OptBool.new('SCREENSHOT', [true, "Wheter or not to try to take a screenshot", true])
      ], self.class)

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end

  def run_host(ip)

    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      virtual_machines = vim_get_vms
      virtual_machines.each do |vm|
        print_good YAML.dump(vm)
        report_note(
          :host  => rhost,
          :type  => "vmware.esx.vm",
          :data  => vm,
          :port  => rport,
          :proto => 'tcp',
          :update => :unique_data
        )
        next unless datastore['SCREENSHOT'] and vm['runtime']['powerState'] == 'poweredOn'
        print_status "Attempting to take screenshot of #{vm['name']}...."
        screenshot = vim_take_screenshot(vm, datastore['USERNAME'], datastore['PASSWORD'] )
        case screenshot
        when :error
          print_error "Screenshot failed"
          next
        when :expired
          vim_do_login(datastore['USERNAME'], datastore['PASSWORD'])
          retry_result = vim_take_screenshot(vm, datastore['USERNAME'], datastore['PASSWORD'] )
          if retry_result == :error or retry_result == :expired
            print_error "Screenshot failed"
          else
            ss_path = store_loot("host.vmware.screenshot", "image/png", datastore['RHOST'], retry_result, "#{vm['name']}_screenshot.png", "Screenshot of VM #{vm['name']}")
            print_good "Screenshot Saved to #{ss_path}"
          end
        else
          ss_path = store_loot("host.vmware.screenshot", "image/png", datastore['RHOST'], screenshot, "screenshot.png", "Screenshot of VM #{vm['name']}")
          print_good "Screenshot Saved to #{ss_path}"
        end
      end

      f = store_loot('host.vmware.vms', "text/plain", datastore['RHOST'], YAML.dump(virtual_machines) , "#{datastore['RHOST']}_esx_vms.txt", "VMWare ESX Virtual Machines")
      vprint_status("VM info stored in: #{f}")
    else
      print_error "Login Failure on #{ip}"
      return
    end
  end

end
