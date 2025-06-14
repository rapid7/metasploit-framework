# -*- coding: binary -*-


module Msf::Post::Unix

  #
  # @return [Boolean] true if session is running as uid=0
  #
  def is_root?
    (cmd_exec('id -u').to_s.gsub(/[^\d]/, '') == '0')
  end

  #
  # Gets the pid of the current session
  # @return [String]
  #
  def get_session_pid
    cmd_exec("echo $PPID").to_s
  end

  #
  # Returns an array of hashes each representing a user
  # Keys are name, uid, gid, info, dir and shell
  #
  def get_users
    users = []
    etc_passwd = nil
    [
      "/etc/passwd",
      "/etc/security/passwd",
      "/etc/master.passwd",
    ].each { |f|
      if file_exist?(f)
        etc_passwd = f
        break
      end
    }
    cmd_out = read_file(etc_passwd).split("\n")
    cmd_out.each do |l|
      entry = {}
      user_field = l.split(":")
      entry[:name] = user_field[0]
      entry[:uid] = user_field[2]
      entry[:gid] = user_field[3]
      entry[:info] = user_field[4]
      entry[:dir] = user_field[5]
      entry[:shell] = user_field[6]
      users << entry
    end
    return users
  end

  #
  # Returns an array of hashes each hash representing a user group
  # Keys are name, gid and users
  #
  def get_groups
    groups = []
    group = '/etc/group'
    if file_exist?(group)
      cmd_out = read_file(group).split("\n")
      cmd_out.each do |l|
        entry = {}
        user_field = l.split(":")
        entry[:name] = user_field[0]
        entry[:gid] = user_field[2]
        entry[:users] = user_field[3]
        groups << entry
      end
    end
    return groups
  end

  #
  # Enumerates the user directories in /Users or /home
  #
  def enum_user_directories
    user_dirs = []

    # get all user directories from /etc/passwd
    passwd = '/etc/passwd'
    if file_exist?(passwd)
      read_file(passwd).each_line do |passwd_line|
        user_dirs << passwd_line.split(':')[5]
      end
    end

    # also list other common places for home directories in the event that
    # the users aren't in /etc/passwd (LDAP, for example)
    case session.platform
    when 'osx'
      user_dirs << cmd_exec('ls /Users').each_line.map { |l| "/Users/#{l}" }
    else
      user_dirs << cmd_exec('ls /home').each_line.map { |l| "/home/#{l}" }
    end

    user_dirs.flatten!
    user_dirs.compact!
    user_dirs.sort!
    user_dirs.uniq!
    user_dirs
  end

  #
  # It returns the username of the current user
  # @return [String] with username
  #
  def whoami
    shellpid = get_session_pid()
    status = read_file("/proc/#{shellpid}/status")
    status.each_line do |line|
      split = line.split(":")
      if split[0] == "Uid"
        regex = /.*\s(.*)\s/
        useridtmp = split[1]
        userid = useridtmp[regex, 1]
        uid = userid.to_s
        passwd = read_file("/etc/passwd")
        passwd.each_line do |line|
          parts = line.split(":")
          uid_passwd = parts[2].to_s
          user = parts[0].to_s
          if uid_passwd == uid
            return user
          end
        end
      end
    end
  end
end
