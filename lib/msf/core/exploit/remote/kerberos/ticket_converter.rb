module Msf::Exploit::Remote::Kerberos
  module TicketConverter

    # Converts a kirbi format cred to a ccache format cred
    # @param [Rex::Proto::Kerberos::Model::KrbCred] krb_cred
    # @return [Rex::Proto::Kerberos::CredentialCache::Krb5Ccache]
    def self.kirbi_to_ccache(krb_cred)
      enc_krb_part = Rex::Proto::Kerberos::Model::EncKrbCredPart.decode(krb_cred.enc_part.cipher)
      krb_cred_info = enc_krb_part.ticket_info[0]
      cc_principal = Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal.new(
        name_type: krb_cred_info.pname.name_type,
        components: krb_cred_info.pname.name_string,
        realm: krb_cred_info.prealm
      )
      client_principal = cc_principal.clone
      server_principal = Rex::Proto::Kerberos::CredentialCache::Krb5CcachePrincipal.new(
        name_type: krb_cred_info.sname.name_type,
        components: krb_cred_info.sname.name_string,
        realm: krb_cred_info.srealm
      )

      Rex::Proto::Kerberos::CredentialCache::Krb5Ccache.new(
        default_principal: cc_principal,
        credentials: [
          {
            client: client_principal,
            server: server_principal,
            keyblock: {
              enctype: krb_cred_info.key.type,
              data: krb_cred_info.key.value
            },
            authtime: krb_cred_info.auth_time,
            starttime: krb_cred_info.start_time,
            endtime: krb_cred_info.end_time,
            renew_till: krb_cred_info.renew_till,
            ticket_flags: krb_cred_info.flags.to_i,
            ticket: krb_cred.tickets[0].encode
          }
        ]
      )
    end

    # Converts a ccache format cred to a kirbi format cred
    # @param [Rex::Proto::Kerberos::CredentialCache::Krb5Ccache] ccache
    # @return [Rex::Proto::Kerberos::Model::KrbCred]
    def self.ccache_to_kirbi(ccache)
      cred = ccache.credentials[0]
      krb_cred = Rex::Proto::Kerberos::Model::KrbCred.new
      krb_cred.pvno = 5
      krb_cred.msg_type = 0x16
      krb_cred.tickets = [Rex::Proto::Kerberos::Model::Ticket.decode(cred.ticket.value)]
      ticket_info = Rex::Proto::Kerberos::Model::KrbCredInfo.new
      key = Rex::Proto::Kerberos::Model::EncryptionKey.new(
        type: cred.keyblock.enctype,
        value: cred.keyblock.data
      )
      ticket_info.key = key
      ticket_info.prealm = cred.client.realm
      pname = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: cred.client.name_type,
        name_string: cred.client.components
      )
      ticket_info.pname = pname
      ticket_info.flags = Rex::Proto::Kerberos::Model::KdcOptionFlags.new(cred.ticket_flags.value)
      ticket_info.auth_time = cred.authtime
      ticket_info.start_time = cred.starttime.get
      ticket_info.end_time = cred.endtime.get
      ticket_info.renew_till = cred.renew_till.get
      sname = Rex::Proto::Kerberos::Model::PrincipalName.new(
        name_type: cred.server.name_type,
        name_string: cred.server.components
      )
      ticket_info.sname = sname
      ticket_info.srealm = cred.server.realm

      enc_part = Rex::Proto::Kerberos::Model::EncryptedData.new(
        etype: key.type,
        cipher: Rex::Proto::Kerberos::Model::EncKrbCredPart.new(ticket_info: [ticket_info]).encode
      )
      krb_cred.enc_part = enc_part
      krb_cred
    end
  end
end
