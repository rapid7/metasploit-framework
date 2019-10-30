##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Etcd
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Etcd Version Scanner',
      'Description' => %q(
        This module connections to etcd API endpoints, typically on 2379/TCP, and attempts
        to obtain the version of etcd.
      ),
      'References' => [
        ['URL', 'https://elweb.co/the-security-footgun-in-etcd']
      ],
      'Author' => [
        'Giovanni Collazo <hello@gcollazo.com>', # discovery
        'Jon Hart <jon_hart@rapid7.com>' # msf module
      ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => "Mar 16 2018"
    )
  end

  def run_host(_target_host)
    if (banner = fingerprint_service(target_uri.to_s))
      print_good("#{peer}: #{banner}")
    end
  end
end
