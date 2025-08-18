# encoding: utf-8
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  # Optional SNMP client mixin (available in MSF)
  begin
    include Msf::Exploit::Remote::SNMPClient
    HAVE_SNMP = true
  rescue ::LoadError, ::NameError
    HAVE_SNMP = false
  end

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ESC/POS Network Printer Discovery',
      'Description' => %q{
        Identifies network printers that are likely ESC/POS-compatible (e.g., Epson TM series,
        Star Micronics, BIXOLON) and therefore candidates for raw TCP/9100 command injection.
        The module checks for an open raw printing port (9100), can optionally send a *safe*
        ESC/POS status query (DLE EOT 1), and can optionally query SNMP for sysDescr and MAC OUIs.
        Results are recorded to the database via services and notes.
      },
      'Author'      => ['FutileSkills'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RHOSTS,
        Opt::RPORT(9100),
        OptInt.new('TIMEOUT', [true, 'TCP read timeout (ms)', 1000]),
        OptBool.new('ACTIVE_CHECK', [true, 'Send safe ESC/POS status (DLE EOT 1) after connect', true]),
        OptBool.new('USE_SNMP', [true, 'Attempt SNMP sysDescr/MAC fingerprinting', true]),
        OptString.new('SNMP_COMMUNITY', [true, 'SNMP v2c community (if USE_SNMP)', 'public']),
        OptInt.new('SNMP_TIMEOUT', [true, 'SNMP timeout (ms)', 1000]),
        OptInt.new('SNMP_RETRIES', [true, 'SNMP retries', 1]),
      ]
    )

    register_advanced_options(
      [
        OptString.new('VENDOR_REGEX', [true,
          'Regex (case-insensitive) for vendor match in sysDescr/MAC OUI',
          '(epson|escpos|tm-\w+|star\s*micronics|bixolon|pos[-\s]*x|citizen|sewoo)']),
        OptString.new('OUI_HINTS', [true,
          'Comma-separated OUI prefixes (hex, no separators) to hint printer vendors',
          '0080C7,00:80:C7,00D0:12,001BA9,0030F9,3C:2A:F4'])
      ]
    )
  end

  # Safe ESC/POS device status query (DLE EOT n). Many printers ignore; any response is a hint.
  DLE_EOT1 = "\x10\x04\x01".b

  def setup
    @vendor_rx = Regexp.new(datastore['VENDOR_REGEX'], Regexp::IGNORECASE)
    @oui_hints = datastore['OUI_HINTS'].to_s.split(/[,\s]+/).map { |s| s.delete(':-').upcase }.reject(&:empty?)
    super
  end

  def run_host(ip)
    found = {
      rport_open: false,
      escpos_resp: nil,
      snmp_sysdescr: nil,
      snmp_macs: [],
      vendor_match: []
    }

    # 1) Check TCP/9100
    vprint_status("#{ip}:#{rport} checking TCP")
    begin
      connect(true, { 'RHOST' => ip })
      found[:rport_open] = true
      store_service(host: ip, port: rport, proto: 'tcp', name: 'printer-raw-9100')
      if datastore['ACTIVE_CHECK']
        sock.put(DLE_EOT1)
        sock.flush
        resp = sock.get_once(datastore['TIMEOUT'].to_i / 1000.0)
        found[:escpos_resp] = resp && resp.bytes.map { |b| sprintf('0x%02X', b) }.join(' ')
      end
    rescue ::Rex::ConnectionError
      found[:rport_open] = false
    ensure
      disconnect rescue nil
    end

    # 2) Optional SNMP fingerprinting
    if datastore['USE_SNMP']
      if !HAVE_SNMP
        vprint_error("#{ip}: SNMP mixin not available in this environment")
      else
        begin
          snmp = connect_snmp(host: ip,
                              community: datastore['SNMP_COMMUNITY'],
                              version: :SNMPv2c,
                              timeout: datastore['SNMP_TIMEOUT'].to_i,
                              retries: datastore['SNMP_RETRIES'].to_i)
          if snmp
            # sysDescr.0
            sys_descr = snmp.get_value('1.3.6.1.2.1.1.1.0') rescue nil
            found[:snmp_sysdescr] = sys_descr if sys_descr && !sys_descr.empty?
            # ifPhysAddress walk
            macs = []
            begin
              snmp.walk('1.3.6.1.2.1.2.2.1.6') do |vb|
                mac = vb.value.is_a?(String) ? vb.value.unpack('C*').map { |b| sprintf('%02X', b) }.join(':') : nil
                macs << mac if mac && mac !~ /^00(:00){5}$/i
              end
            rescue ::StandardError
            end
            found[:snmp_macs] = macs.uniq
            snmp.close
          end
        rescue ::StandardError => e
          vprint_error("#{ip}: SNMP error: #{e.class}: #{e.message}")
        end
      end
    end

    # 3) Heuristics / vendor hints
    if found[:snmp_sysdescr].to_s =~ @vendor_rx
      found[:vendor_match] << 'sysDescr'
    end
    unless found[:snmp_macs].empty? || @oui_hints.empty?
      found[:snmp_macs].each do |m|
        compact = m.delete(':').upcase
        # Compare first 6 hex chars (OUI)
        if @oui_hints.any? { |h| compact.start_with?(h.delete(':')) }
          found[:vendor_match] << "OUI(#{m})"
        end
      end
    end

    # 4) Decision & reporting
    likely = found[:rport_open] && (found[:escpos_resp] || !found[:vendor_match].empty?)

    if likely
      print_good("#{ip}: Likely ESC/POS printer (tcp/9100 open; hints=#{(found[:vendor_match].empty? ? 'none' : found[:vendor_match].join(', '))}; escpos_resp=#{found[:escpos_resp] || 'none'})")
    elsif found[:rport_open]
      print_status("#{ip}: tcp/9100 open, but no ESC/POS hints found (may still be raw-print capable).")
    else
      vprint_status("#{ip}: tcp/9100 closed")
    end

    # Persist useful details
    note_data = {
      module: fullname,
      escpos_candidate: likely,
      tcp_9100_open: found[:rport_open],
      escpos_status_bytes: found[:escpos_resp],
      snmp_sysdescr: found[:snmp_sysdescr],
      snmp_macs: found[:snmp_macs],
      vendor_indicators: found[:vendor_match]
    }
    report_note(
      host: ip,
      type: 'printer.escpos.discovery',
      data: note_data,
      update: true
    )
  end
end
