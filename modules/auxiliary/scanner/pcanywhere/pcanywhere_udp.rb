##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'PcAnywhere UDP Service Discovery',
      'Description' => 'Discover active pcAnywhere services through UDP',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'http://www.unixwiz.net/tools/pcascan.txt']
        ]
    )

    register_options(
    [
      Opt::RPORT(5632)
    ])
  end

  def scanner_prescan(batch)
    print_status("Sending pcAnywhere discovery requests to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @results = {}
  end

  def scan_host(ip)
    scanner_send("NQ", ip, datastore['RPORT'])
    scanner_send("ST", ip, datastore['RPORT'])
  end

  def scanner_postscan(batch)
    @results.keys.each do |ip|
      data = @results[ip]
      info = ""

      if data[:name]
        info << "Name: #{data[:name]} "
      end

      if data[:stat]
        info << "- #{data[:stat]} "
      end

      if data[:caps]
        info << "( #{data[:caps]} ) "
      end

      report_service(:host => ip, :port => datastore['RPORT'], :proto => 'udp', :name => "pcanywhere_stat", :info => info)
      report_note(:host => ip, :port => datastore['RPORT'], :proto => 'udp', :name => "pcanywhere_stat", :update => :unique, :ntype => "pcanywhere.status", :data => data )
      print_good("#{ip}:#{datastore['RPORT']} #{info}")
    end
  end

  def scanner_process(data, shost, sport)
    case data
    when /^NR(........................)(........)/

      name = $1.dup
      caps = $2.dup

      name = name.gsub(/_+$/, '').gsub("\x00", '').strip
      caps = caps.gsub(/_+$/, '').gsub("\x00", '').strip

      @results[shost] ||= {}
      @results[shost][:name] = name
      @results[shost][:caps] = caps

    when /^ST(.+)/
      @results[shost] ||= {}
      buff = $1.dup
      stat = 'Unknown'

      if buff[2,1].unpack("C")[0] == 67
        stat = "Available"
      end

      if buff[2,1].unpack("C")[0] == 11
        stat = "Busy"
      end

      @results[shost][:stat] = stat
    else
      print_error("#{shost} Unknown: #{data.inspect}")
    end

  end
end
