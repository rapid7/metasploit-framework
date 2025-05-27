##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SNMP Enumeration Module',
        'Description' => %q{
          This module allows enumeration of any devices with SNMP
          protocol support. It supports hardware, software, and network information.
          The default community used is "public".
        },
        'References' => [
          [ 'URL', 'https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol' ],
          [ 'URL', 'https://net-snmp.sourceforge.io/docs/man/snmpwalk.html' ],
          [ 'URL', 'http://www.nothink.org/codes/snmpcheck/index.php' ],
          [ 'CVE', '1999-0508' ], # Weak password
          [ 'CVE', '1999-0517' ],
          [ 'CVE', '1999-0516' ]
        ],
        'Author' => 'Matteo Cantoni <goony[at]nothink.org>',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  # rubocop:disable Metrics/MethodLength
  def run_host(ip)
    snmp = connect_snmp

    fields_order = [
      'Host IP', 'Hostname', 'Description', 'Contact',
      'Location', 'Uptime snmp', 'Uptime system',
      'System date', 'domain', 'User accounts',
      'Network information', 'Network interfaces',
      'Network IP', 'Routing information',
      'TCP connections and listening ports', 'Listening UDP ports',
      'Network services', 'Share', 'IIS server information',
      'Storage information', 'File system information',
      'Device information', 'Software components',
      'Processes'
    ]

    output_data = { 'Host IP' => ip }

    sys_name = snmp.get_value('1.3.6.1.2.1.1.5.0').to_s
    output_data['Hostname'] = sys_name.strip

    # print connected status after the first query so if there are
    # any timeout or connectivity errors; the code would already
    # have jumped to error handling where the error status is
    # already being displayed.
    print_good("#{ip}, Connected.")

    sys_desc = snmp.get_value('1.3.6.1.2.1.1.1.0').to_s
    sys_desc.gsub!(/^\s+|\s+$|\n+|\r+/, ' ')
    output_data['Description'] = sys_desc.strip

    sys_contact = snmp.get_value('1.3.6.1.2.1.1.4.0').to_s
    output_data['Contact'] = sys_contact.strip

    sys_location = snmp.get_value('1.3.6.1.2.1.1.6.0').to_s
    output_data['Location'] = sys_location.strip

    sys_up_time_instance = snmp.get_value('1.3.6.1.2.1.1.3.0').to_s
    output_data['Uptime system'] = sys_up_time_instance.strip

    hr_system_uptime = snmp.get_value('1.3.6.1.2.1.25.1.1.0').to_s
    output_data['Uptime snmp'] = hr_system_uptime =~ /Null/ ? '-' : hr_system_uptime.strip

    system_date = snmp.get_value('1.3.6.1.2.1.25.1.2.0')
    if system_date.blank? || system_date =~ /Null/ || system_date =~ /^noSuch/
      output_data['System date'] = '-'
    else

      # RFC 2579 - Textual Conventions for SMIv2
      # http://www.faqs.org/rfcs/rfc2579.html

      system_date = system_date.unpack('C*')

      output_data['System date'] = format(
        '%<year>d-%<month>d-%<day>d %<hour>02d:%<minutes>02d:%<seconds>02d.%<tenths>d',
        year: system_date[0] * 256 + system_date[1],
        month: system_date[2] || 0,
        day: system_date[3] || 0,
        hour: system_date[4] || 0,
        minutes: system_date[5] || 0,
        seconds: system_date[6] || 0,
        tenths: system_date[7] || 0
      )
    end

    if (sys_desc =~ /Windows/)
      dom_primary_domain = snmp.get_value('1.3.6.1.4.1.77.1.4.1.0').to_s

      output_data['Domain'] = dom_primary_domain.strip

      users = []

      snmp.walk(['1.3.6.1.4.1.77.1.2.25.1.1', '1.3.6.1.4.1.77.1.2.25.1']) do |user, _entry|
        users.push([[user.value]])
      end

      if !users.empty?
        output_data['User accounts'] = users
      end
    end

    network_information = {}

    ip_forwarding = snmp.get_value('1.3.6.1.2.1.4.1.0')

    if ip_forwarding == 0 || ip_forwarding == 2
      ip_forwarding = 'no'
      network_information['IP forwarding enabled'] = ip_forwarding
    elsif ip_forwarding == 1
      ip_forwarding = 'yes'
      network_information['IP forwarding enabled'] = ip_forwarding
    end

    ip_default_ttl = snmp.get_value('1.3.6.1.2.1.4.2.0')
    if ip_default_ttl.to_s !~ /Null/
      network_information['Default TTL'] = ip_default_ttl
    end

    tcp_in_segs = snmp.get_value('1.3.6.1.2.1.6.10.0')
    if tcp_in_segs.to_s !~ /Null/
      network_information['TCP segments received'] = tcp_in_segs
    end

    tcp_out_segs = snmp.get_value('1.3.6.1.2.1.6.11.0')
    if tcp_out_segs.to_s !~ /Null/
      network_information['TCP segments sent'] = tcp_out_segs
    end

    tcp_retrans_segs = snmp.get_value('1.3.6.1.2.1.6.12.0')
    if tcp_retrans_segs.to_s !~ /Null/
      network_information['TCP segments retrans'] = tcp_retrans_segs
    end

    ip_in_receives = snmp.get_value('1.3.6.1.2.1.4.3.0')
    if ip_in_receives.to_s !~ /Null/
      network_information['Input datagrams'] = ip_in_receives
    end

    ip_in_delivers = snmp.get_value('1.3.6.1.2.1.4.9.0')
    if ip_in_delivers.to_s !~ /Null/
      network_information['Delivered datagrams'] = ip_in_delivers
    end

    ip_out_requests = snmp.get_value('1.3.6.1.2.1.4.10.0')
    if ip_out_requests.to_s !~ /Null/
      network_information['Output datagrams'] = ip_out_requests
    end

    unless network_information.blank?
      output_data['Network information'] = network_information
    end

    network_interfaces = []

    # rubocop:disable Metrics/ParameterLists
    snmp.walk([
      '1.3.6.1.2.1.2.2.1.1', '1.3.6.1.2.1.2.2.1.2', '1.3.6.1.2.1.2.2.1.6',
      '1.3.6.1.2.1.2.2.1.3', '1.3.6.1.2.1.2.2.1.4', '1.3.6.1.2.1.2.2.1.5',
      '1.3.6.1.2.1.2.2.1.10', '1.3.6.1.2.1.2.2.1.16', '1.3.6.1.2.1.2.2.1.7'
    ]) do |index, descr, mac, type, mtu, speed, inoc, outoc, status|
      # rubocop:enable Metrics/ParameterLists
      ifindex = index.value
      ifdescr = descr.value
      ifmac = mac.value.to_s =~ /noSuchInstance/ ? 'unknown' : mac.value.unpack('H2H2H2H2H2H2').join(':')
      iftype = type.value
      ifmtu = mtu.value
      ifspeed = speed.value.to_s =~ /noSuchInstance/ ? 'unknown' : speed.value.to_i / 1000000
      ifinoc = inoc.value
      ifoutoc = outoc.value
      ifstatus = status.value

      case iftype
      when 1
        iftype = 'other'
      when 2
        iftype = 'regular1822'
      when 3
        iftype = 'hdh1822'
      when 4
        iftype = 'ddn-x25'
      when 5
        iftype = 'rfc877-x25'
      when 6
        iftype = 'ethernet-csmacd'
      when 7
        iftype = 'iso88023-csmacd'
      when 8
        iftype = 'iso88024-tokenBus'
      when 9
        iftype = 'iso88025-tokenRing'
      when 10
        iftype = 'iso88026-man'
      when 11
        iftype = 'starLan'
      when 12
        iftype = 'proteon-10Mbit'
      when 13
        iftype = 'proteon-80Mbit'
      when 14
        iftype = 'hyperchannel'
      when 15
        iftype = 'fddi'
      when 16
        iftype = 'lapb'
      when 17
        iftype = 'sdlc'
      when 18
        iftype = 'ds1'
      when 19
        iftype = 'e1'
      when 20
        iftype = 'basicISDN'
      when 21
        iftype = 'primaryISDN'
      when 22
        iftype = 'propPointToPointSerial'
      when 23
        iftype = 'ppp'
      when 24
        iftype = 'softwareLoopback'
      when 25
        iftype = 'eon'
      when 26
        iftype = 'ethernet-3Mbit'
      when 27
        iftype = 'nsip'
      when 28
        iftype = 'slip'
      when 29
        iftype = 'ultra'
      when 30
        iftype = 'ds3'
      when 31
        iftype = 'sip'
      when 32
        iftype = 'frame-relay'
      else
        iftype = 'unknown'
      end

      case ifstatus
      when 1
        ifstatus = 'up'
      when 2
        ifstatus = 'down'
      when 3
        ifstatus = 'testing'
      else
        ifstatus = 'unknown'
      end

      network_interfaces.push({
        'Interface' => "[ #{ifstatus} ] #{ifdescr}",
        'Id' => ifindex,
        'Mac Address' => ifmac,
        'Type' => iftype,
        'Speed' => "#{ifspeed} Mbps",
        'MTU' => ifmtu,
        'In octets' => ifinoc,
        'Out octets' => ifoutoc
      })
    end

    if !network_interfaces.empty?
      output_data['Network interfaces'] = network_interfaces
    end

    network_ip = []

    snmp.walk([
      '1.3.6.1.2.1.4.20.1.2', '1.3.6.1.2.1.4.20.1.1',
      '1.3.6.1.2.1.4.20.1.3', '1.3.6.1.2.1.4.20.1.4'
    ]) do |ifid, ipaddr, netmask, bcast|
      network_ip.push([ifid.value, ipaddr.value, netmask.value, bcast.value])
    end

    if !network_ip.empty?
      output_data['Network IP'] = [['Id', 'IP Address', 'Netmask', 'Broadcast']] + network_ip
    end

    routing = []

    snmp.walk([
      '1.3.6.1.2.1.4.21.1.1', '1.3.6.1.2.1.4.21.1.7',
      '1.3.6.1.2.1.4.21.1.11', '1.3.6.1.2.1.4.21.1.3'
    ]) do |dest, hop, mask, metric|
      if metric.value.to_s.empty?
        metric.value = '-'
      end
      routing.push([dest.value, hop.value, mask.value, metric.value])
    end

    if !routing.empty?
      output_data['Routing Information'] = [['Destination', 'Next Hop', 'Mask', 'Metric']] + routing
    end

    tcp = []

    snmp.walk([
      '1.3.6.1.2.1.6.13.1.2', '1.3.6.1.2.1.6.13.1.3', '1.3.6.1.2.1.6.13.1.4',
      '1.3.6.1.2.1.6.13.1.5', '1.3.6.1.2.1.6.13.1.1'
    ]) do |ladd, lport, radd, rport, state|
      if ladd.value.to_s.empty? || ladd.value.to_s =~ /noSuchInstance/
        ladd = '-'
      else
        ladd = ladd.value
      end

      if lport.value.to_s.empty? || lport.value.to_s =~ /noSuchInstance/
        lport = '-'
      else
        lport = lport.value
      end

      if radd.value.to_s.empty? || radd.value.to_s =~ /noSuchInstance/
        radd = '-'
      else
        radd = radd.value
      end

      if rport.value.to_s.empty? || rport.value.to_s =~ /noSuchInstance/
        rport = '-'
      else
        rport = rport.value
      end

      case state.value
      when 1
        state = 'closed'
      when 2
        state = 'listen'
      when 3
        state = 'synSent'
      when 4
        state = 'synReceived'
      when 5
        state = 'established'
      when 6
        state = 'finWait1'
      when 7
        state = 'finWait2'
      when 8
        state = 'closeWait'
      when 9
        state = 'lastAck'
      when 10
        state = 'closing'
      when 11
        state = 'timeWait'
      when 12
        state = 'deleteTCB'
      else
        state = 'unknown'
      end

      tcp.push([ladd, lport, radd, rport, state])
    end

    if !tcp.empty?
      output_data['TCP connections and listening ports'] = [['Local address', 'Local port', 'Remote address', 'Remote port', 'State']] + tcp
    end

    udp = []

    snmp.walk(['1.3.6.1.2.1.7.5.1.1', '1.3.6.1.2.1.7.5.1.2']) do |ladd, lport|
      udp.push([ladd.value, lport.value])
    end

    if !udp.empty?
      output_data['Listening UDP ports'] = [['Local address', 'Local port']] + udp
    end

    if (sys_desc =~ /Windows/)
      network_services = []
      n = 0
      snmp.walk(['1.3.6.1.4.1.77.1.2.3.1.1', '1.3.6.1.4.1.77.1.2.3.1.2']) do |name, _installed|
        network_services.push([n, name.value])
        n += 1
      end

      if !network_services.empty?
        output_data['Network services'] = [['Index', 'Name']] + network_services
      end

      share = []

      snmp.walk([
        '1.3.6.1.4.1.77.1.2.27.1.1', '1.3.6.1.4.1.77.1.2.27.1.2', '1.3.6.1.4.1.77.1.2.27.1.3'
      ]) do |name, path, comment|
        share.push({ ' Name' => name.value, '  Path' => path.value, '  Comment' => comment.value })
      end

      if !share.empty?
        output_data['Share'] = share
      end

      iis = {}

      http_total_bytes_sent_low_word = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.2.0')
      if http_total_bytes_sent_low_word.to_s !~ /Null/
        iis['TotalBytesSentLowWord'] = http_total_bytes_sent_low_word
      end

      http_total_bytes_received_low_word = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.4.0')
      if http_total_bytes_received_low_word.to_s !~ /Null/
        iis['TotalBytesReceivedLowWord'] = http_total_bytes_received_low_word
      end

      http_total_files_sent = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.5.0')
      if http_total_files_sent.to_s !~ /Null/
        iis['TotalFilesSent'] = http_total_files_sent
      end

      http_current_anonymous_users = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.6.0')
      if http_current_anonymous_users.to_s !~ /Null/
        iis['CurrentAnonymousUsers'] = http_current_anonymous_users
      end

      http_current_non_anonymous_users = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.7.0')
      if http_current_non_anonymous_users.to_s !~ /Null/
        iis['CurrentNonAnonymousUsers'] = http_current_non_anonymous_users
      end

      http_total_anonymous_users = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.8.0')
      if http_total_anonymous_users.to_s !~ /Null/
        iis['TotalAnonymousUsers'] = http_total_anonymous_users
      end

      http_total_non_anonymous_users = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.9.0')
      if http_total_non_anonymous_users.to_s !~ /Null/
        iis['TotalNonAnonymousUsers'] = http_total_non_anonymous_users
      end

      http_max_anonymous_users = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.10.0')
      if http_max_anonymous_users.to_s !~ /Null/
        iis['MaxAnonymousUsers'] = http_max_anonymous_users
      end

      http_max_non_anonymous_users = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.11.0')
      if http_max_non_anonymous_users.to_s !~ /Null/
        iis['MaxNonAnonymousUsers'] = http_max_non_anonymous_users
      end

      http_current_connections = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.12.0')
      if http_current_connections.to_s !~ /Null/
        iis['CurrentConnections'] = http_current_connections
      end

      http_max_connections = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.13.0')
      if http_max_connections.to_s !~ /Null/
        iis['MaxConnections'] = http_max_connections
      end

      http_connection_attempts = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.14.0')
      if http_connection_attempts.to_s !~ /Null/
        iis['ConnectionAttempts'] = http_connection_attempts
      end

      http_logon_attempts = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.15.0')
      if http_logon_attempts.to_s !~ /Null/
        iis['LogonAttempts'] = http_logon_attempts
      end

      http_total_gets = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.16.0')
      if http_total_gets.to_s !~ /Null/
        iis['Gets'] = http_total_gets
      end

      http_total_posts = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.17.0')
      if http_total_posts.to_s !~ /Null/
        iis['Posts'] = http_total_posts
      end

      http_total_heads = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.18.0')
      if http_total_heads.to_s !~ /Null/
        iis['Heads'] = http_total_heads
      end

      http_total_others = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.19.0')
      if http_total_others.to_s !~ /Null/
        iis['Others'] = http_total_others
      end

      http_total_cgi_requests = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.20.0')
      if http_total_cgi_requests.to_s !~ /Null/
        iis['CGIRequests'] = http_total_cgi_requests
      end

      # Was this supposed to be "CGI" requests?
      http_total_bgi_requests = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.21.0')
      if http_total_bgi_requests.to_s !~ /Null/
        iis['BGIRequests'] = http_total_bgi_requests
      end

      http_total_not_found_errors = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.22.0')
      if http_total_not_found_errors.to_s !~ /Null/
        iis['NotFoundErrors'] = http_total_not_found_errors
      end

      if !iis.empty?
        output_data['IIS server information'] = iis
      end
    end

    storage_information = []

    snmp.walk([
      '1.3.6.1.2.1.25.2.3.1.1', '1.3.6.1.2.1.25.2.3.1.2', '1.3.6.1.2.1.25.2.3.1.3',
      '1.3.6.1.2.1.25.2.3.1.4', '1.3.6.1.2.1.25.2.3.1.5', '1.3.6.1.2.1.25.2.3.1.6'
    ]) do |index, type, descr, allocation, size, used|
      case type.value.to_s
      when /^1.3.6.1.2.1.25.2.1.1$/
        type.value = 'Other'
      when /^1.3.6.1.2.1.25.2.1.2$/
        type.value = 'Ram'
      when /^1.3.6.1.2.1.25.2.1.3$/
        type.value = 'Virtual Memory'
      when /^1.3.6.1.2.1.25.2.1.4$/
        type.value = 'Fixed Disk'
      when /^1.3.6.1.2.1.25.2.1.5$/
        type.value = 'Removable Disk'
      when /^1.3.6.1.2.1.25.2.1.6$/
        type.value = 'Floppy Disk'
      when /^1.3.6.1.2.1.25.2.1.7$/
        type.value = 'Compact Disc'
      when /^1.3.6.1.2.1.25.2.1.8$/
        type.value = 'RamDisk'
      when /^1.3.6.1.2.1.25.2.1.9$/
        type.value = 'Flash Memory'
      when /^1.3.6.1.2.1.25.2.1.10$/
        type.value = 'Network Disk'
      else
        type.value = 'unknown'
      end

      allocation.value = 'unknown' if allocation.value.to_s =~ /noSuchInstance/
      size.value = 'unknown' if size.value.to_s =~ /noSuchInstance/
      used.value = 'unknown' if used.value.to_s =~ /noSuchInstance/

      storage_information.push([[descr.value], [index.value], [type.value], [allocation.value], [size.value], [used.value]])
    end

    if !storage_information.empty?
      storage = []
      storage_information.each do |a, b, c, d, e, f|
        s = {}

        e = number_to_human_size(e, d)
        f = number_to_human_size(f, d)

        s['Description'] = a
        s['Device id'] = b
        s['Filesystem type'] = c
        s['Device unit'] = d
        s['Memory size'] = e
        s['Memory used'] = f

        storage.push(s)
      end
      output_data['Storage information'] = storage
    end

    file_system = {}

    hr_fs_index = snmp.get_value('1.3.6.1.2.1.25.3.8.1.1.1')
    if hr_fs_index.to_s !~ /Null/
      file_system['Index'] = hr_fs_index
    end

    hr_fs_mount_point = snmp.get_value('1.3.6.1.2.1.25.3.8.1.2.1')
    if hr_fs_mount_point.to_s !~ /Null/
      file_system['Mount point'] = hr_fs_mount_point
    end

    hr_fs_remote_mount_point = snmp.get_value('1.3.6.1.2.1.25.3.8.1.3.1')
    if hr_fs_remote_mount_point.to_s !~ /Null/ && hr_fs_remote_mount_point.to_s !~ /^noSuch/
      if hr_fs_remote_mount_point.empty?
        hr_fs_remote_mount_point = '-'
      end
      file_system['Remote mount point'] = hr_fs_remote_mount_point
    end

    hr_fs_type = snmp.get_value('1.3.6.1.2.1.25.3.8.1.4.1')

    case hr_fs_type.to_s
    when /^1.3.6.1.2.1.25.3.9.1$/
      hr_fs_type = 'Other'
    when /^1.3.6.1.2.1.25.3.9.2$/
      hr_fs_type = 'Unknown'
    when /^1.3.6.1.2.1.25.3.9.3$/
      hr_fs_type = 'BerkeleyFFS'
    when /^1.3.6.1.2.1.25.3.9.4$/
      hr_fs_type = 'Sys5FS'
    when /^1.3.6.1.2.1.25.3.9.5$/
      hr_fs_type = 'Fat'
    when /^1.3.6.1.2.1.25.3.9.6$/
      hr_fs_type = 'HPFS'
    when /^1.3.6.1.2.1.25.3.9.7$/
      hr_fs_type = 'HFS'
    when /^1.3.6.1.2.1.25.3.9.8$/
      hr_fs_type = 'MFS'
    when /^1.3.6.1.2.1.25.3.9.9$/
      hr_fs_type = 'NTFS'
    when /^1.3.6.1.2.1.25.3.9.10$/
      hr_fs_type = 'VNode'
    when /^1.3.6.1.2.1.25.3.9.11$/
      hr_fs_type = 'Journaled'
    when /^1.3.6.1.2.1.25.3.9.12$/
      hr_fs_type = 'iso9660'
    when /^1.3.6.1.2.1.25.3.9.13$/
      hr_fs_type = 'RockRidge'
    when /^1.3.6.1.2.1.25.3.9.14$/
      hr_fs_type = 'NFS'
    when /^1.3.6.1.2.1.25.3.9.15$/
      hr_fs_type = 'Netware'
    when /^1.3.6.1.2.1.25.3.9.16$/
      hr_fs_type = 'AFS'
    when /^1.3.6.1.2.1.25.3.9.17$/
      hr_fs_type = 'DFS'
    when /^1.3.6.1.2.1.25.3.9.18$/
      hr_fs_type = 'Appleshare'
    when /^1.3.6.1.2.1.25.3.9.19$/
      hr_fs_type = 'RFS'
    when /^1.3.6.1.2.1.25.3.9.20$/
      hr_fs_type = 'DGCFS'
    when /^1.3.6.1.2.1.25.3.9.21$/
      hr_fs_type = 'BFS'
    when /^1.3.6.1.2.1.25.3.9.22$/
      hr_fs_type = 'FAT32'
    when /^1.3.6.1.2.1.25.3.9.23$/
      hr_fs_type = 'LinuxExt2'
    else
      hr_fs_type = 'Null'
    end

    if hr_fs_type.to_s !~ /Null/
      file_system['Type'] = hr_fs_type
    end

    hr_fs_access = snmp.get_value('1.3.6.1.2.1.25.3.8.1.5.1')
    if hr_fs_access.to_s !~ /Null/
      file_system['Access'] = hr_fs_access
    end

    hr_fs_bootable = snmp.get_value('1.3.6.1.2.1.25.3.8.1.6.1')
    if hr_fs_bootable.to_s !~ /Null/
      file_system['Bootable'] = hr_fs_bootable
    end

    if !file_system.empty?
      output_data['File system information'] = file_system
    end

    device_information = []

    snmp.walk([
      '1.3.6.1.2.1.25.3.2.1.1', '1.3.6.1.2.1.25.3.2.1.2',
      '1.3.6.1.2.1.25.3.2.1.5', '1.3.6.1.2.1.25.3.2.1.3'
    ]) do |index, type, status, descr|
      case type.value.to_s
      when /^1.3.6.1.2.1.25.3.1.1$/
        type.value = 'Other'
      when /^1.3.6.1.2.1.25.3.1.2$/
        type.value = 'Unknown'
      when /^1.3.6.1.2.1.25.3.1.3$/
        type.value = 'Processor'
      when /^1.3.6.1.2.1.25.3.1.4$/
        type.value = 'Network'
      when /^1.3.6.1.2.1.25.3.1.5$/
        type.value = 'Printer'
      when /^1.3.6.1.2.1.25.3.1.6$/
        type.value = 'Disk Storage'
      when /^1.3.6.1.2.1.25.3.1.10$/
        type.value = 'Video'
      when /^1.3.6.1.2.1.25.3.1.11$/
        type.value = 'Audio'
      when /^1.3.6.1.2.1.25.3.1.12$/
        type.value = 'Coprocessor'
      when /^1.3.6.1.2.1.25.3.1.13$/
        type.value = 'Keyboard'
      when /^1.3.6.1.2.1.25.3.1.14$/
        type.value = 'Modem'
      when /^1.3.6.1.2.1.25.3.1.15$/
        type.value = 'Parallel Port'
      when /^1.3.6.1.2.1.25.3.1.16$/
        type.value = 'Pointing'
      when /^1.3.6.1.2.1.25.3.1.17$/
        type.value = 'Serial Port'
      when /^1.3.6.1.2.1.25.3.1.18$/
        type.value = 'Tape'
      when /^1.3.6.1.2.1.25.3.1.19$/
        type.value = 'Clock'
      when /^1.3.6.1.2.1.25.3.1.20$/
        type.value = 'Volatile Memory'
      when /^1.3.6.1.2.1.25.3.1.21$/
        type.value = 'Non Volatile Memory'
      else
        type.value = 'unknown'
      end

      case status.value
      when 1
        status.value = 'unknown'
      when 2
        status.value = 'running'
      when 3
        status.value = 'warning'
      when 4
        status.value = 'testing'
      when 5
        status.value = 'down'
      else
        status.value = 'unknown'
      end

      descr.value = 'unknown' if descr.value.to_s =~ /noSuchInstance/

      device_information.push([index.value, type.value, status.value, descr.value])
    end

    if !device_information.empty?
      output_data['Device information'] = [['Id', 'Type', 'Status', 'Descr']] + device_information
    end

    software_list = []

    snmp.walk(['1.3.6.1.2.1.25.6.3.1.1', '1.3.6.1.2.1.25.6.3.1.2']) do |index, name|
      software_list.push([index.value, name.value])
    end

    if !software_list.empty?
      output_data['Software components'] = [['Index', 'Name']] + software_list
    end

    process_interfaces = []

    snmp.walk([
      '1.3.6.1.2.1.25.4.2.1.1', '1.3.6.1.2.1.25.4.2.1.2', '1.3.6.1.2.1.25.4.2.1.4',
      '1.3.6.1.2.1.25.4.2.1.5', '1.3.6.1.2.1.25.4.2.1.7'
    ]) do |id, name, path, param, status|
      if status.value == 1
        status.value = 'running'
      elsif status.value == 2
        status.value = 'runnable'
      else
        status.value = 'unknown'
      end

      process_interfaces.push([id.value, status.value, name.value, path.value, param.value])
    end

    if !process_interfaces.empty?
      output_data['Processes'] = [['Id', 'Status', 'Name', 'Path', 'Parameters']] + process_interfaces
    end

    print_line("\n[*] System information:\n")

    line = ''
    width = 30  # name field width
    twidth = 32 # table like display cell width

    fields_order.each do |k|
      next unless output_data.key?(k)

      v = output_data[k]

      case v
      when Array
        content = ''

        v.each do |a|
          case a
          when Hash
            a.each do |sk, sv|
              sk = truncate_to_twidth(sk, twidth)
              content << sk.to_s
              content << ' ' * [0, width - sk.length].max
              content << ": #{sv}\n"
            end
          when Array
            a.each do |sv|
              sv = sv.to_s.strip
              # I don't like cutting info
              # sv = truncate_to_twidth(sv, twidth)
              content << sprintf('%-20s', sv)
            end
          else
            content << sprintf("    %s\n", a)
          end
          content << "\n"
        end

        report_note(
          host: ip,
          proto: 'udp',
          sname: 'snmp',
          port: datastore['RPORT'].to_i,
          type: "snmp.#{k}",
          data: { content: content }
        )

        line << "\n[*] #{k}:\n\n#{content}"

      when Hash
        content = ''
        v.each do |sk, sv|
          sk = truncate_to_twidth(sk, twidth)
          content << sk.to_s
          content << ' ' * [0, width - sk.length].max
          content << ": #{sv}\n"
        end

        report_note(
          host: ip,
          proto: 'udp',
          sname: 'snmp',
          port: datastore['RPORT'].to_i,
          type: "snmp.#{k}",
          data: { content: content }
        )

        line << "\n[*] #{k}:\n\n#{content}"
        content << "\n"
      else
        if v.nil? || v.empty? || v =~ /Null/
          v = '-'
        end

        report_note(
          host: ip,
          proto: 'udp',
          sname: 'snmp',
          port: datastore['RPORT'].to_i,
          type: "snmp.#{k}",
          data: { content: v }
        )

        k = truncate_to_twidth(k, twidth)
        line << k.to_s
        line << ' ' * [0, width - k.length].max
        line << ": #{v}\n"
      end
    end

    print_line(line)
    print_line('')
  rescue SNMP::RequestTimeout
    print_error("#{ip} SNMP request timeout.")
  rescue Rex::ConnectionError
    print_error("#{ip} Connection refused.")
  rescue SNMP::InvalidIpAddress
    print_error("#{ip} Invalid IP address. Check it with 'snmpwalk tool'.")
  rescue SNMP::UnsupportedVersion
    print_error("#{ip} Unsupported SNMP version specified. Select from '1' or '2c'.")
  rescue SNMP::ParseError
    print_error("#{ip} Encountered an SNMP parsing error while trying to enumerate the host.")
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError => e
    print_error("Unknown error: #{e.class} #{e}")
    elog(e)
  ensure
    disconnect_snmp
  end
  # rubocop:enable Metrics/MethodLength

  def truncate_to_twidth(string, twidth)
    string.slice(0..twidth - 2)
  end

  def number_to_human_size(size, unit)
    size = size.first.to_i * unit.first.to_i

    if size < 1024
      "#{size} bytes"
    elsif size < 1024.0 * 1024.0
      '%.02f KB' % (size / 1024.0)
    elsif size < 1024.0 * 1024.0 * 1024.0
      '%.02f MB' % (size / 1024.0 / 1024.0)
    else
      '%.02f GB' % (size / 1024.0 / 1024.0 / 1024.0)
    end
  end
end
