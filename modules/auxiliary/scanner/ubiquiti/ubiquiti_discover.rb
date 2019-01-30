##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Ubiquiti Discovery Scanner',
        'Description' => 'Detects Ubiquiti devices using a UDP discovery service',
        'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
        'License'     => MSF_LICENSE,
        'References'  =>
          [
            ['URL', 'https://www.us-cert.gov/ncas/alerts/TA14-017A'],
            ['URL', 'https://community.ubnt.com/t5/airMAX-General-Discussion/airOS-airMAX-and-management-access/td-p/2654023']
          ]
      )
    )

    register_options([
      Opt::RPORT(10001)
    ])
  end

  def build_probe
    @probe = "\x01\x00\x00\x00"
  end

  def scanner_process(data, shost, sport)
    offset = 0
    if data.length < 4
        return
    end

    type, length = data.unpack("vn")
    offset += 4
    if type != 1 || length != data.length - offset
        return
    end

    remaining = data.length - offset
    info = {'ips' =>  [], 'macs' => []}
    while remaining > 0
      type, length = data.slice(offset, 3).unpack("Cn")
      offset += 3
      remaining -= 4

      field_data = data.slice(offset, length)
      offset += length
      remaining -= length
      if type == 0x0b
        info['name'] = field_data
      elsif type == 0x01
        # process the MAC
        info['macs'] << field_data.each_byte.map { |b| b.to_s(16) }.join(':')
      elsif type == 0x02
        # process a MAC and IP
        info['macs'] << field_data.slice(0,6).each_byte.map { |b| b.to_s(16) }.join(':')
        info['ips'] << field_data.slice(6,4).each_byte.map { |b| b.to_i }.join('.')
        #info['macs'].append(':'.join("{:02x}".format(b) for b in struct.unpack("BBBBBB", field_data[:6])))
        #info['ips'].append('.'.join(str(int(b)) for b in struct.unpack("BBBB", field_data[6:10])))
      elsif type == 0x14
        info['model_long'] = field_data
      elsif type == 0x0c
        info['model_short'] = field_data
      elsif type == 0x03
        info['firmware'] = field_data
      elsif  type == 0x0d
        info['essid'] = field_data
      else
      end
    end

    if ! info['macs'].any?
      info.delete('macs')
    end
    info['macs'] = info['macs'].sort.uniq

    if ! info['ips'].any?
      info.delete('ips')
    end
    info['ips'] = info['ips'].sort.uniq

    if info.empty?
      return
    end

    print_good("#{shost}:#{sport} #{info}")
    report_service(
      host: shost,
      proto: 'udp',
      port: rport,
      info: info,
      name: 'ubiquiti_discovery'
    )
  end
end
