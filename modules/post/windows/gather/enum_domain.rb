##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Accounts

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Enumerate Domain',
        'Description' => %q{
          This module identifies the primary Active Directory domain name
          and domain controller.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => %w[meterpreter shell powershell],
        'Author' => ['Joshua Abraham <jabra[at]rapid7.com>'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_net_resolve_host
            ]
          }
        }
      )
    )
  end

  def resolve_host(host)
    return host if Rex::Socket.dotted_ip?(host)

    return unless client.respond_to?(:net)

    vprint_status("Resolving host #{host}")

    result = client.net.resolve.resolve_host(host)

    return if result[:ip].blank?

    result[:ip]
  end

  def run
    domain = get_domain_name

    fail_with(Failure::Unknown, 'Could not retrieve domain name. Is the host part of a domain?') unless domain && !domain.empty?

    print_good("Domain FQDN: #{domain}")

    report_note(
      host: session,
      type: 'windows.domain',
      data: { domain: domain },
      update: :unique_data
    )

    netbios_domain_name = domain.split('.').first.upcase

    print_good("Domain NetBIOS Name: #{netbios_domain_name}")

    domain_controller = get_primary_domain_controller

    fail_with(Failure::Unknown, 'Could not retrieve domain controller name') unless domain_controller && !domain_controller.empty?

    dc_ip = resolve_host(domain_controller)
    if dc_ip.nil?
      print_good("Domain Controller: #{domain_controller}")
    else
      print_good("Domain Controller: #{domain_controller} (IP: #{dc_ip})")
      report_host({
        host: dc_ip,
        name: domain_controller,
        info: "Domain controller for #{domain}"
      })
    end
  end
end
