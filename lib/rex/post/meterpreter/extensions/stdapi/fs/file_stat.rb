# -*- coding: binary -*-

require 'rex/post/file_stat'
require 'rex/post/meterpreter/extensions/stdapi/stdapi'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

###
#
# This class wrappers gathering information about a given file and implements
# the Rex::Post::FileStat interface in terms of data acquisition.
#
###
class FileStat < Rex::Post::FileStat

  class << self
    attr_accessor :client
  end

  @@struct_stat = [
    'st_dev',     4,  # 0
    'st_ino',     2,  # 4
    'st_mode',    2,  # 6
    'st_nlink',   2,  # 8
    'st_uid',     2,  # 10
    'st_gid',     2,  # 12
    'pad1',       2,  # 14
    'st_rdev',    4,  # 16
    'st_size',    4,  # 20
    'st_atime',   8,  # 24
    'st_mtime',   8,  # 32
    'st_ctime',   8,  # 40
  ]

  ##
  #
  # Constructor
  #
  ##

  #
  # Returns an instance of a FileStat object.
  #
  def initialize(file)
    self.stathash = stat(file) if (file)
  end

  #
  # Swaps in a new stat hash.
  #
  def update(stat_buf)
    elem   = @@struct_stat
    hash   = {}
    offset = 0
    index  = 0

    while (index < elem.length)
      size = elem[index + 1]

      value   = stat_buf[offset, size].unpack(size == 2 ? 'v' : 'V')[0]
      offset += size

      hash[elem[index]] = value

      index += 2
    end

    return (self.stathash = hash)
  end

protected

  ##
  #
  # Initializer
  #
  ##

  #
  # Gets information about the supplied file and returns a populated
  # hash to the requestor.
  #
  def stat(file)
    request = Packet.create_request('stdapi_fs_stat')

    request.add_tlv(TLV_TYPE_FILE_PATH, self.class.client.unicode_filter_decode( file ))

    response = self.class.client.send_request(request)
    stat_buf = response.get_tlv(TLV_TYPE_STAT_BUF).value

    # Next, we go through the returned stat_buf and fix up the values
    # and insert them into a hash
    return update(stat_buf)
  end

end

end; end; end; end; end; end

