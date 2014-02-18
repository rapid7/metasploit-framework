##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Services

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Gather Service Info Enumeration",
      'Description'          => %q{
        This module will query the system for services and display name and
        configuration info for each returned service. It allows you to
        optionally search the credentials, path, or start type for a string
        and only return the results that match. These query operations are
        cumulative and if no query strings are specified, it just returns all
        services.  NOTE: If the script hangs, windows firewall is most likely
        on and you did not migrate to a safe process (explorer.exe for
        example).
        },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['Keith Faber', 'Kx499']
    ))
    register_options(
      [
        OptString.new('CRED', [ false, 'String to search credentials for' ]),
        OptString.new('PATH', [ false, 'String to search path for' ]),
        OptEnum.new('TYPE', [false, 'Service startup Option', 'All', ['All', 'Auto', 'Manual', 'Disabled' ]])
      ], self.class)
  end


  def run

    # set vars
    qcred = datastore["CRED"]
    qpath = datastore["PATH"]

    if qcred
      qcred = qcred.downcase
      print_status("Credential Filter: " + qcred)
    end

    if qpath
      qpath = qpath.downcase
      print_status("Executable Path Filter: " + qpath)
    end

    if datastore["TYPE"] == "All"
      qtype = nil
    else
      qtype = datastore["TYPE"].downcase
      print_status("Start Type Filter: " + qtype)
    end

    print_status("#{session.session_host} - Listing Service Info for matching services:")
    each_service do |sname|
      srv_conf = {}

      # make sure we got a service name
      if sname
        begin
          srv_conf = service_info(sname)
        rescue => e
          print_error("Error enumerating service '#{sname}': #{e}")
          next
        end

        # filter service based on filters passed, they are cumulative
        if qcred && !srv_conf['Credentials'].downcase.include?(qcred)
          next
        end
        if qpath && !srv_conf['Command'].downcase.include?(qpath)
          next
        end
        # There may not be a 'Startup', need to check nil
        if qtype && !(srv_conf['Startup'] || '').downcase.include?(qtype)
          next
        end

        print_status("\tName: #{sname}")
        print_good("\t\tStartup: #{srv_conf['Startup']}")
        print_good("\t\tCommand: #{srv_conf['Command']}")
        print_good("\t\tCredentials: #{srv_conf['Credentials']}")
      else
        print_error("Problem enumerating services")
      end

    end
  end

end
