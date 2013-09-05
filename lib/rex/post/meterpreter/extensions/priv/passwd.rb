#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Priv

###
#
# This class wraps a SAM hash entry.
#
###
class SamUser

  #
  # Initializes the class from a hash string like this:
  #
  # Administrator:500:aad3b435b51404eeaadfb435b51404ee:31d6cfe0d16de931b73c59d7e0c089c0:::
  #
  def initialize(hash_str)
    self.user_name, self.user_id, self.lanman, self.ntlm = hash_str.split(/:/)

    self.hash_string = hash_str
  end

  #
  # Returns the hash string that was supplied to the constructor.
  #
  def to_s
    hash_string
  end

  #
  # The raw hash string that was passed to the class constructor.
  #
  attr_reader :hash_string
  #
  # The username from the SAM database entry.
  #
  attr_reader :user_name
  #
  # The user's unique identifier from the SAM database.
  #
  attr_reader :user_id
  #
  # The LM hash.
  #
  attr_reader :lanman
  #
  # The NTLM hash.
  #
  attr_reader :ntlm

protected

  attr_writer :hash_string, :user_name, :user_id, :lanman, :ntlm # :nodoc:

end

end; end; end; end; end
