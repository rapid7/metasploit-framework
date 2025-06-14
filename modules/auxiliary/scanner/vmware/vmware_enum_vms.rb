##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'VMware Enumerate Virtual Machines',
      'Description' => %(
        This module attempts to discover virtual machines on any VMware instance
        running the web interface. This would include ESX/ESXi and VMware Server.
      ),
      'Author' => ['theLightCosine'],
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true },
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [ true, 'The username to Authenticate with.', 'root' ]),
        OptString.new('PASSWORD', [ true, 'The password to Authenticate with.', 'password' ]),
        OptBool.new('SCREENSHOT', [true, 'Whether or not to try to take a screenshot', true])
      ]
    )
  end

  def run_host(ip)
    if vim_do_login(datastore['USERNAME'], datastore['PASSWORD']) == :success
      virtual_machines = vim_get_vms
      virtual_machines.each do |vm|
        print_good YAML.dump(vm)
        report_note(
          host: rhost,
          type: 'vmware.esx.vm',
          data: { virtual_machine: vm },
          port: rport,
          proto: 'tcp',
          update: :unique_data
        )
        next unless datastore['SCREENSHOT'] && (vm['runtime']['powerState'] == 'poweredOn')

        print_status "Attempting to take screenshot of #{vm['name']}...."
        screenshot = vim_take_screenshot(vm, datastore['USERNAME'], datastore['PASSWORD'])
        case screenshot
        when :error
          print_error 'Screenshot failed'
          next
        when :expired
          vim_do_login(datastore['USERNAME'], datastore['PASSWORD'])
          retry_result = vim_take_screenshot(vm, datastore['USERNAME'], datastore['PASSWORD'])
          if (retry_result == :error) || (retry_result == :expired)
            print_error 'Screenshot failed'
          else
            ss_path = store_loot('host.vmware.screenshot', 'image/png', datastore['RHOST'], retry_result, "#{vm['name']}_screenshot.png", "Screenshot of VM #{vm['name']}")
            print_good "Screenshot Saved to #{ss_path}"
          end
        else
          ss_path = store_loot('host.vmware.screenshot', 'image/png', datastore['RHOST'], screenshot, 'screenshot.png', "Screenshot of VM #{vm['name']}")
          print_good "Screenshot Saved to #{ss_path}"
        end
      end

      f = store_loot('host.vmware.vms', 'text/plain', datastore['RHOST'], YAML.dump(virtual_machines), "#{datastore['RHOST']}_esx_vms.txt", 'VMware ESX Virtual Machines')
      vprint_good("VM info stored in: #{f}")
    else
      print_error "Login Failure on #{ip}"
      return
    end
  end
end
