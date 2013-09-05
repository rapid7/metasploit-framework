require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/netapi'

class Metasploit3 < Msf::Post

  include Msf::Post::Common
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::NetAPI

  def initialize(info={})
    super( update_info( info,
      'Name'	       => 'Windows Gather Enumerate Active Domain Users',
      'Description'  => %q{
          This module will enumerate computers included in the primary Domain and attempt
          to list all locations the targeted user has sessions on. If a the HOST option is specified
          the module will target only that host. If the HOST is specified and USER is set to nil, all users
          logged into that host will be returned.'
        },
        'License'      => MSF_LICENSE,
        'Author'       => [ 'Etienne Stalmans <etienne[at]sensepost.com>'],
        'Platform'     => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
    ))
    register_options(
      [
        OptString.new('USER',    [false, 'Target User for NetSessionEnum']),
        OptString.new('HOST',    [false, 'Target a specific host']),
      ], self.class)
  end

  def run
    sessions = []
    user = datastore['USER']
    host = datastore['HOST']

    if host
      if user
        print_status("Attempting to identify #{user} on #{host}...")
      else
        print_status("Attempting to get all logged in users on #{host}...")
      end
      sessions = net_session_enum(host, user)
    elsif user
      domain = getdomain

      unless domain.empty?
        print_status ("Using domain: #{domain}")
        print_status ("Getting list of domain hosts...")
      end

      hosts = net_server_enum(SV_TYPE_ALL, domain)

      if hosts
        len = hosts.count
        print_status("#{len} host(s) found")

        hosts.each do |host|
          sessions << net_session_enum(host[:name], user)
        end
      end

      sessions.flatten!
    else
      print_error("Invalid options, either HOST or USER must be specified.")
      return
    end

    if sessions.nil? or sessions.count == 0
      print_error("No sessions found")
      return
    else
      print_status("#{sessions.count} session(s) identified")
    end

    if sessions and sessions.count > 0
      sessions.each do |s|
        if s
          print_good("#{s[:username]} logged in at #{s[:hostname]} and has been idle for #{s[:idletime]} seconds")
        end
      end
    end
  end

  # Gets the Domain Name -- originally from enum_domain.rb -- Don't really need this, more informational
  def getdomain
    domain = nil
    begin
      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
      v_name = "DCName"
      domain_dc = registry_getvaldata(subkey, v_name)
      dom_info =	domain_dc.split('.')
      domain = dom_info[1].upcase
    rescue
      print_error("This host is not part of a domain.")
    end
    return domain
  end
end
