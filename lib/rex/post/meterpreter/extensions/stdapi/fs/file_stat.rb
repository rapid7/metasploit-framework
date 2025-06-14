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

  ##
  #
  # Constructor
  #
  ##

  #
  # Returns an instance of a FileStat object.
  #
  def initialize(file)
    super
    stat(file) if (file)
  end

protected
  #
  # Gets information about the supplied file and returns a populated
  # hash to the requester.
  #
  def stat(file)
    request = Packet.create_request(COMMAND_ID_STDAPI_FS_STAT)

    request.add_tlv(TLV_TYPE_FILE_PATH, self.class.client.unicode_filter_decode( file ))

    response = self.class.client.send_request(request)
    stat_buf = response.get_tlv(TLV_TYPE_STAT_BUF)

    unless stat_buf
      stat_buf = response.get_tlv(TLV_TYPE_STAT_BUF32)
      return update32(stat_buf.value)
    end

    # Next, we go through the returned stat_buf and fix up the values
    # and insert them into a hash
    return update(stat_buf.value)
  end

end

end; end; end; end; end; end

