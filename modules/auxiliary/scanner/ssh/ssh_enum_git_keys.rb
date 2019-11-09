##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Test SSH Github Access',
        'Description'   => %q(
          This module will attempt to test remote Git access using
          (.ssh/id_* private keys). This works against GitHub and
          GitLab by default, but can easily be extended to support
          more server types.
        ),
        'License'       => MSF_LICENSE,
        'Author'        => ['Wyatt Dahlenburg (@wdahlenb)'],
        'Platform'      => ['linux'],
        'SessionTypes'  => ['shell', 'meterpreter'],
        'References'    => [['URL', 'https://help.github.com/en/articles/testing-your-ssh-connection']]
      )
    )

    register_options(
      [
        OptPath.new('KEY_FILE', [false, 'Filename of a private key.', nil]),
        OptPath.new('KEY_DIR', [false, 'Directory of several keys. Filenames will be recursivley found matching id_* (Ex: /home/user/.ssh)', nil]),
        OptString.new('GITSERVER', [false, 'Optional parameter to specify alternate Git Server (GitHub, GitLab, etc)', 'github.com'])
      ]
    )
    deregister_options(
      'RHOST', 'RHOSTS', 'PASSWORD', 'PASS_FILE', 'BLANK_PASSWORDS', 'USER_AS_PASS', 'USERPASS_FILE', 'DB_ALL_PASS', 'DB_ALL_CREDS'
    )

  end

  # OPTPath will revert to pwd when set back to ""
  def key_dir
    datastore['KEY_DIR'] != `pwd`.strip ? datastore['KEY_DIR'] : ""
  end

  def key_file
    datastore['KEY_FILE'] != `pwd`.strip ? datastore['KEY_FILE'] : ""
  end

  def has_passphrase?(file)
    response = `ssh-keygen -y -P "" -f #{file} 2>&1`
    return response.include? 'incorrect passphrase'
  end

  def read_keyfile(file)
    if file.is_a? Array
      keys = []
      file.each do |dir_entry|
        next unless ::File.readable? dir_entry

        keys.concat(read_keyfile(dir_entry))
      end
      return keys
    else
      keyfile = ::File.open(file, "rb") { |f| f.read(f.stat.size) }
    end
    keys = []
    this_key = []
    in_key = false
    keyfile.split("\n").each do |line|
      in_key = true if (line =~ /^-----BEGIN ([RD]SA|OPENSSH) PRIVATE KEY-----/)
      this_key << line if in_key
      if (line =~ /^-----END ([RD]SA|OPENSSH) PRIVATE KEY-----/)
        in_key = false
        keys << file unless has_passphrase?(file)
      end
    end
    if keys.empty?
      print_error "SSH - No valid keys found"
    end
    return keys
  end

  def parse_user(output)
    vprint_status("SSH Test: #{output}")
    if (output =~ /You\'ve successfully authenticated/)
      return output.match(/Hi (.*)\! You\'ve successfully authenticated/)[1]
    elsif (output =~ /Welcome to GitLab, \@(.*)\!$/)
      return output.match(/Welcome to GitLab, \@(.*)\!$/)[1]
    end
  end

  def check_git_keys(queue)
    threads = datastore['THREADS']
    return {} if queue.blank?

    threads = 1 if threads <= 0

    results = {}
    until queue.empty?
      t = []
      threads = 1 if threads <= 0

      if queue.length < threads
        threads = queue.length
      end

      begin
        1.upto(threads) do
          t << framework.threads.spawn("Module(#{refname})", false, queue.shift) do |file|
            Thread.current.kill unless file

            config_contents = "Host gitserver\n\tUser git\n\tHostname #{datastore['GITSERVER']}\n\tPreferredAuthentications publickey\n\tIdentityFile #{file}\n"

            rand_file = Rex::Quickfile.new
            rand_file.puts config_contents
            rand_file.close

            output = `ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -T -F #{rand_file.path} gitserver 2>&1`
            if output.include? "\n"
              output = output.split("\n")[-1]
            end
            user = parse_user(output)
            if user
              results[file] = user
            end
            rand_file.delete
          end
        end
        t.map(&:join)
      rescue ::Timeout::Error
      ensure
        t.each { |x| x.kill rescue nil }
      end
    end
    return results
  end

  def test_keys
    if key_file && File.readable?(key_file)
      keys = Array(read_keyfile(key_file))
    elsif !key_dir.nil? && !key_dir.empty?
      return :missing_keyfile unless (File.directory?(key_dir) && File.readable?(key_dir))

      @key_files ||= Dir.glob("#{key_dir}/**/id_*", File::FNM_DOTMATCH).reject { |f| f.include? '.pub' }
      keys = read_keyfile(@key_files)
    else
      return {}
    end

    check_git_keys(keys)
  end

  def run
    if datastore['KEY_FILE'].nil? && datastore['KEY_DIR'].nil?
      fail_with Failure::BadConfig, 'Please specify a KEY_FILE or KEY_DIR'
    elsif !(key_file.blank? ^ key_dir.blank?)
      fail_with Failure::BadConfig, 'Please only specify one KEY_FILE or KEY_DIR'
    end

    results = test_keys
    return if results.empty?

    keys_table = Rex::Text::Table.new(
      'Header' => "Git Access Data",
      'Columns' => [ 'Key Location', 'User Access' ]
    )

    results.each do |key, user|
      keys_table << [key, user]
    end

    print_line(keys_table.to_s)
  end
end
