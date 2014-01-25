##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HP LaserJet Printer SNMP Enumeration',
      'Description' => 'This module allows enumeration of files previously printed.
        It provides details as filename, client, timestamp and username informations.
        The default community used is "public".',
      'References'  =>
        [
          [ 'URL', 'http://en.wikipedia.org/wiki/Simple_Network_Management_Protocol' ],
          [ 'URL', 'http://net-snmp.sourceforge.net/docs/man/snmpwalk.html' ],
          [ 'URL', 'http://www.nothink.org/perl/snmpcheck/' ],
          [ 'URL', 'http://www.securiteam.com/securitynews/5AP0S2KGVS.html' ],
          [ 'URL', 'http://stuff.mit.edu/afs/athena/dept/cron/tools/share/mibs/290923.mib' ],
        ],
      'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
      'License'     => MSF_LICENSE
      ))
  end

  def run_host(ip)
    begin
      snmp = connect_snmp

      vprint_status("Connecting to #{ip}")

      output_data = []

      output_data << "IP address  : #{ip}"

      sysName = snmp.get_value('1.3.6.1.2.1.1.5.0').to_s
      output_data << "Hostname    : #{sysName.strip}"

      sysDesc = snmp.get_value('1.3.6.1.2.1.1.1.0').to_s
      sysDesc.gsub!(/^\s+|\s+$|\n+|\r+/, ' ')
      output_data << "Description : #{sysDesc.strip}"

      sysContact = snmp.get_value('1.3.6.1.2.1.1.4.0').to_s
      output_data << "Contact     : #{sysContact.strip}" if not sysContact.empty?

      sysLocation = snmp.get_value('1.3.6.1.2.1.1.6.0').to_s
      output_data << "Location    : #{sysLocation.strip}" if not sysLocation.empty?

      output_data << ""

      snmp.walk([
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.1",    # job-info-name1  - document name1
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.2",    # job-info-name2  - document name2
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.1", # job-info-attr-1 - username
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.2", # job-info-attr-2 - machine name
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.3", # job-info-attr-3 - domain (?)
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.4", # job-info-attr-4 - timestamp
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.6", # job-info-attr-6 - application name
        "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6.5.23.7", # job-info-attr-7 - application command
      ]) do |name1,name2,username,client,domain,timestamp,app_name,app_command|

        filename = name1.value.to_s + name2.value.to_s

        if (username.value.to_s !~ /noSuchInstance/)
          if username.value.to_s =~ /^JobAcct(\d+)=(.*)/
            username = $2
          end
        else
          username = ''
        end

        if (client.value.to_s !~ /noSuchInstance/)
          if client.value.to_s =~ /^JobAcct(\d+)=(.*)/
            client = $2
          end
        else
          client = ''
        end

        if (domain.value.to_s !~ /noSuchInstance/)
          if domain.value.to_s =~ /^JobAcct(\d+)=(.*)/
            domain = $2
          end
        else
          domain = ''
        end

        if (timestamp.value.to_s !~ /noSuchInstance/)
          if timestamp.value.to_s =~ /^JobAcct(\d+)=(.*)/
            timestamp = $2
          end
        else
          timestamp = ''
        end

        if (app_name.value.to_s !~ /noSuchInstance/)
          if app_name.value.to_s =~ /^JobAcct(\d+)=(.*)/
            app_name = $2
          end
        else
          app_name = ''
        end

        if (app_command.value.to_s !~ /noSuchInstance/)
          if app_command.value.to_s =~ /^JobAcct(\d+)=(.*)/
            app_command = $2
          end
        else
          app_command = ''
        end

        if not timestamp.empty?
          output_data << "File name   : #{filename}"
          output_data << "Username    : #{username}" if not username.empty?
          output_data << "Client      : #{client}" if not client.empty?
          output_data << "Domain      : #{domain}" if not domain.empty?
          output_data << "Timestamp   : #{timestamp}" if not timestamp.empty?
          output_data << "Application : #{app_name} (#{app_command})" if not app_name.empty?
          output_data << ""
        end
      end

      output_data.each do |row|
        print_good("#{row}")
      end

      disconnect_snmp

    rescue SNMP::RequestTimeout
      vprint_status("#{ip}, SNMP request timeout.")
    rescue Errno::ECONNREFUSED
      vprint_status("#{ip}, Connection refused.")
    rescue SNMP::InvalidIpAddress
      vprint_status("#{ip}, Invalid IP Address. Check it with 'snmpwalk tool'.")
    rescue ::Interrupt
    raise $!
    rescue ::Exception => e
      vprint_error("#{ip}, Unknown error: #{e.class} #{e}")
    end
  end
end
