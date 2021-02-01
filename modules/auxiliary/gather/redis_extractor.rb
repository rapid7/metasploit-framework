##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Redis

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Redis Extractor',
      'Description'    => %q{
        This module connects to a Redis instance and retrieves keys and data stored.
      },
      'Author'     => ['Geoff Rainville noncenz[at]ultibits.com'],
      'License'    => MSF_LICENSE,
      'References' => [['URL', 'https://redis.io/topics/protocol']]

    ))
  end

  MIN_REDIS_VERSION = '2.8.0'
  @kv

  # Recurse to assemble the full list of keys
  def scan(offset)
    response = redis_command('scan',offset).split("\n")
    new_offset = response[2].strip # cursor position for next iteration or zero if we are done
    key_offset=5 # location of first key in each response set.
    while key_offset < response.length()
      key = response[key_offset].strip
      @kv.push([key,value_for_key(key)])
      key_offset += 2 # skip over byte count and only read data fields.
    end
    scan(new_offset) unless new_offset.eql? "0"
  end

  def value_for_key(key)
    keyType = redis_command('TYPE',key)
    case keyType
    when '+string'
      return redis_command('get',key).split("\n")[1..-1].join("\n")
    when '+list'
      listContent = redis_command('LRANGE',key,'0','-1')
      return decode_redis_array(listContent)
    when '+set'
      setContent = redis_command('SMEMBERS',key)
      return decode_redis_array(setContent)
    when '+zset'
      setContent = redis_command('ZRANGE',key,'0','-1')
      return decode_redis_array(setContent)
    when '+hash'
      hashContent = decode_redis_array(redis_command('HGETALL',key))
      result = []
      (0..hashContent.length-1).step(2) do |x|
        result.append([hashContent[x],hashContent[x+1]])
      end
      return result
    else
      return 'unknown key type ' + keyType
    end
  end

  def decode_redis_array(data)
    decoded = []
    x= /\*(?<elements>\S+)\r\n/ =~ data
    data.slice! "*#{elements}\r\n"
    while data
      x = /\$(?<length>\S+)\r/ =~ data
      data.slice! "$#{length}\r\n"
      decoded.append(data[0..length.to_i-1])
      data = data[(length.to_i+2)..-1]
    end
    print_error("Error decoding Redis array. Some data may be missing or invalid.") if elements.to_i != decoded.length
    return decoded

  end

  # Connect to Redis and ensure compatibility.
  def redis_connect
    begin
      connect
      # Note: Full INFO payload fails occasionally. Using server filter until Redis library can be fixed
      if (info_data = redis_command('INFO','server')) && /redis_version:(?<redis_version>\S+)/ =~ info_data
        print_good("Connected to Redis version #{redis_version}")
      end

      # Some connection attempts such as incorrect password set fail silently in the Redis library.
      if !info_data
        print_error("Unable to connect to Redis")
        print_error("Set verbose true to troubleshoot") if !datastore["VERBOSE"]
        return
      end

      # Ensure version compatability
      if (Gem::Version.new(redis_version) < Gem::Version.new(MIN_REDIS_VERSION))
        print_status("Module supports Redis #{MIN_REDIS_VERSION} or higher.")
        return
      end

      # Connection was sucessful
      return info_data

    rescue Msf::Auxiliary::Failed => e
      # This error trips when auth is required but password not set
      print_error("Unable to connect to Redis: " + e.message)
      return

    rescue Rex::ConnectionTimeout
      print_error("Timed out trying to connect to Redis")
      return

    rescue
      print_error("Unknown error trying to connect to Redis")
      return
    end
  end

  def check_host(ip)
    info_data=redis_connect
    if(info_data)
      if /os:(?<os_ver>.*)/ =~ info_data
        print_status("OS is #{os_ver} ")
      end

      if /keys=(?<keys>\S+),expires=/ =~ info_data
        print_status("Redis reports #{keys} keys stored")
      end

      if /used_memory_peak_human:(?<bytes>.*)/ =~ info_data
        print_status("#{bytes.chomp} bytes stored")
      end
    end
    disconnect
    return info_data ? Msf::Exploit::CheckCode::Appears : Msf::Exploit::CheckCode::Unknown
  end

  def get_keyspace
    ks = redis_command('INFO','keyspace')
    ks = ks.split("\n")[2..-1]
    result = []
    ks.each do |k|
      if /db(?<db>\S+):/ =~ k && /keys=(?<keys>\S+),expires/ =~ k
        result.append([db,keys])
      end
    end
    return result
  end

  def run_host(ip)
    if(!redis_connect)
      disconnect
      return
    end

    keyspace = get_keyspace
    keyspace.each do |space|
      print_status("Extracting about #{space[1]} keys from databaase #{space[0]}")
      redis_command('SELECT',space[0])
      @kv=[]
      scan("0")

      if(@kv.length == 0)
        print_status("No keys returned")
      else

        # Report data in terminal
        result_table = Rex::Text::Table.new(
          'Header'  => "Data from #{peer} database #{space[0]}",
          'Indent'  => 1,
          'Columns' => [ 'Key', 'Value' ]
        )
        @kv.each { |pair| result_table << pair }
        print_line
        print_line("#{result_table}")

        # Store data as loot
        csv=[]
        @kv.each { |pair| csv << pair.to_csv }
        path = store_loot("redis.dump_db#{space[0]}", 'text/plain', rhost,csv.join, 'redis.txt', 'Redis extractor')
        print_good("Redis data stored at #{path}")
      end
    end
    disconnect
  end
end
