##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::LDAP::Server

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Native LDAP Server (Example)',
        'Description' => %q{
          This module provides a Rex based LDAP service to expose the
          native Rex LDAP server functionality created during log4shell
          development.
        },
        'Author' => [
          'RageLtMan <rageltman[at]sempervictus>', # infrastructure
          'Spencer McIntyre' # syntactically sane/correct Ruby LDAP object actions from early effort on l4j2 scanner
        ],
        'License' => MSF_LICENSE,
        'References' => [],
        'Actions' => [
          [ 'Service', { 'Description' => 'Run LDAP server' } ]
        ],
        'PassiveActions' => [
          'Service'
        ],
        'DefaultAction' => 'Service',
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  #
  # Wrapper for service execution
  #
  def run
    start_service
    service.wait
  rescue Rex::BindFailed => e
    print_error "Failed to bind to port #{datastore['SRVPORT']}: #{e.message}"
  end

  #
  # Creates Proc to handle incoming requests
  #
  def on_dispatch_request(client, data)
    return if data.strip.empty?

    data.extend(Net::BER::Extensions::String)
    begin
      pdu = Net::LDAP::PDU.new(data.read_ber!(Net::LDAP::AsnSyntax))
      vprint_status("LDAP request data remaining: #{data}") if !data.empty?
      resp = case pdu.app_tag
             when Net::LDAP::PDU::BindRequest # bind request
               # vprint_good("Received LDAP bind request from #{client} - #{pp pdu}")
               client.authenticated = true
               service.encode_ldap_response(
                 pdu.message_id,
                 Net::LDAP::ResultCodeSuccess,
                 '',
                 '',
                 Net::LDAP::PDU::BindResult
               )
             when Net::LDAP::PDU::SearchRequest # search request
               if client.authenticated || datastore['LDAP_AUTH_BYPASS']
                 # Perform query against some loaded LDIF structure
                 filter = Net::LDAP::Filter.parse_ldap_filter(pdu.search_parameters[:filter])
                 attrs = pdu.search_parameters[:attributes].empty? ? :all : pdu.search_parameters[:attributes]
                 res = service.search_ldif(filter, pdu.message_id, attrs)
                 if res.nil? || res.empty?
                   service.encode_ldap_response(
                     pdu.message_id,
                     Net::LDAP::ResultCodeNoSuchObject, '',
                     Net::LDAP::ResultStrings[Net::LDAP::ResultCodeNoSuchObject],
                     Net::LDAP::PDU::SearchResult
                   )
                 else
                   # Send the results and return success message for callback completion
                   client.write(res.join)
                   service.encode_ldap_response(
                     pdu.message_id,
                     Net::LDAP::ResultCodeSuccess, '',
                     Net::LDAP::ResultStrings[Net::LDAP::ResultCodeSuccess],
                     Net::LDAP::PDU::SearchResult
                   )
                 end
               else
                 service.encode_ldap_response(pdu.message_id, 50, '', 'Not authenticated', Net::LDAP::PDU::SearchResult)
               end
             else
               # vprint_status("Received unknown LDAP request from #{client} - #{pp pdu}")
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

end
