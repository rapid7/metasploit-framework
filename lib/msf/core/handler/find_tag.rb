# -*- coding: binary -*-
require 'msf/core/handler/find_port'

module Msf
module Handler

###
#
# This handlers implements tag-based findsock handling.
#
###
module FindTag

  include FindPort

  #
  # Returns the string representation of the handler type, in this case
  # 'find_tag'.
  #
  def self.handler_type
    return "find_tag"
  end

  #
  # Returns the connection oriented general handler type, in this case
  # 'find'.
  #
  def self.general_handler_type
    "find"
  end

  #
  # Initializes the find tag handler with the option that is required for all
  # find-tag based payloads, such as the TAG that will be searched for.
  #
  def initialize(info = {})
    super

    register_advanced_options(
      [
        OptString.new('TAG',
          [
            true,
            "The four byte tag to signify the connection.",
            Rex::Text.rand_text_alphanumeric(4),
          ])
      ], Msf::Handler::FindTag)

    # Eliminate the CPORT option.
    options.remove_option('CPORT')
  end

protected

  #
  # Prefix the stage with this.
  #
  def _find_prefix(sock)
    if (self.respond_to?('stage_prefix') == true)
      self.stage_prefix = _find_tag
    else
      _find_tag
    end
  end

  #
  # Transmits the tag.
  #
  def _send_id(sock)
    if (self.payload_type == Msf::Payload::Type::Single)
      sock.put(_find_tag)

      return _find_tag
    end

    return nil
  end

  #
  # Returns the tag we'll be using.
  #
  def _find_tag
    tag  = (datastore['TAG'] || "msf!")
    tag << ("\x01" * (tag.length - 4))

    return tag[0, 4]
  end

end

end
end
