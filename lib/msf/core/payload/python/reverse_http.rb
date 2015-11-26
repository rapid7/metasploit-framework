# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/uuid/options'

module Msf

module Payload::Python::ReverseHttp

  include Msf::Payload::UUID::Options

  #
  # Return the longest URL that fits into our available space
  #
  def generate_callback_uri
    uri_req_len = 30 + rand(256-30)

    # Generate the short default URL if we don't have enough space
    if self.available_space.nil? || required_space > self.available_space
      uri_req_len = 5
    end

    generate_uri_uuid_mode(:init_python, uri_req_len)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    # Start with our cached default generated size
    space = cached_size

    # Add 100 bytes for the encoder to have some room
    space += 100

    # Make room for the maximum possible URL length
    space += 256

    # The final estimated size
    space
  end

end

end

