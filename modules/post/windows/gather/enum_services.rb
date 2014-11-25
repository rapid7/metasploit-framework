##
# This module requires Metasploit: http://metasploit.com/download
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
        This module will query the system for services and display name and configuration
        info for each returned service. It allows you to optionally search the credentials, path,
        or start type for a string and only return the results that match. These query operations
        are cumulative and if no query strings are specified, it just returns all services.
        NOTE: If the script hangs, windows firewall is most likely on and you did not
        migrate to a safe process (explorer.exe for example).
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
    lootString = ""
    credentialCount = {}
    qcred = datastore["CRED"] || nil
    qpath = datastore["PATH"] || nil
    if datastore["TYPE"] == "All"
      qtype = nil
    else
      qtype = datastore["TYPE"]
    end
    if qcred
      print_status("Credential Filter: #{qcred}")
    end
    if qpath
      print_status("Executable Path Filter: #{qpath}")
    end
    if qtype
      print_status("Start Type Filter: #{qtype}")
    end

    if datastore['VERBOSE']
      print_status("Listing Service Info for matching services:")
    else
      print_status("Detailed output is only printed when VERBOSE is set to True. Running this module can take some time.\n")
    end

    service_list.each do |sname|
      srv_conf = {}
      isgood = true
      # make sure we got a service name
      if sname
        begin
          srv_conf = service_info(sname)
          # filter service based on filters passed, the are cumulative
          if qcred and ! srv_conf['Credentials'].downcase.include? qcred.downcase
            isgood = false
          end
          if qpath and ! srv_conf['Command'].downcase.include? qpath.downcase
            isgood = false
          end
          # There may not be a 'Startup', need to check nil
          if qtype and ! (srv_conf['Startup'] || '').downcase.include? qtype.downcase
            isgood = false
          end
          # count the occurance of specific credentials services are running as
          serviceCred = srv_conf['Credentials'].upcase
          unless serviceCred.empty?
            if credentialCount.has_key?(serviceCred)
              credentialCount[serviceCred] += 1
            else
              credentialCount[serviceCred] = 1
              # let the user know a new service account has been detected for possible lateral
              # movement opportunities
              print_good("New service credential detected: #{sname} is running as '#{srv_conf['Credentials']}'")
            end
          end

          # if we are still good return the info
          if isgood
            msgString = "\tName: #{sname}"
            msgString << "\n\t\tStartup: #{srv_conf['Startup']}"
            #remove invalid char at the end
            commandString = srv_conf['Command']
            commandString.gsub!(/[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]+/n,"")
            msgString << "\n\t\t#{commandString}"
            msgString << "\n\t\tCredentials: #{srv_conf['Credentials']}\n"
            vprint_good(msgString)
            lootString << msgString
          end
        rescue ::Exception => e
          # July 3rd 2014 wchen-r7: Not very sure what exceptions this method is trying to rescue,
          # probably the typical shut-everything-up coding habit. We'll have to fix this later,
          # but for now let's at least print the error for debugging purposes
          print_error("An error occured enumerating service: #{sname}")
          print_error(e.to_s)
        end
      else
        print_error("Problem enumerating services (no service name found)")
      end
    end
      # store loot on completion of collection
      p = store_loot("windows.services", "text/plain", session, lootString, "windows_services.txt", "Windows Services")
      print_good("Loot file stored in: #{p.to_s}")
  end

end
