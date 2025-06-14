# -*- coding: binary -*-
# Copyright (c) 2010, patrickHVE@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * The names of the author may not be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL patrickHVE@googlemail.com BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'thread'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun

#
# A container holding useful API Constants.
#
class ApiConstants

  # This will be lazily loaded in self.manager
  @manager = nil

  # Mutex to ensure we don't add constants more than once via thread races.
  @manager_semaphore = Mutex.new

  class << self
    attr_accessor :manager_semaphore
  end

  def self.inherited(child_class)
    child_class.manager_semaphore = Mutex.new
  end

  #
  # Provides a frozen constant manager for the constants defined in
  # self.add_constants
  #
  def self.manager

    # The first check for nil is to potentially skip the need to synchronize
    if @manager.nil?
      # Looks like we MAY need to load manager
      @manager_semaphore.synchronize do
        # We check once more. Now our options are synchronized
        if @manager.nil?
          @manager = ConstManager.new

          self.add_constants(@manager)

          @manager.freeze
        end
      end
    end

    return @manager
  end
end

#
# Manages our library of constants
#
class ConstManager
  attr_reader :consts

  def initialize(initial_consts = {})
    @consts = {}

    initial_consts.each_pair do |name, value|
      add_const(name, value)
    end
  end

  def add_const(name, value)
    consts[name] = value
  end

  # parses a string containing constants and returns an integer
  # the string can be either "CONST" or "CONST1 | CONST2"
  #
  # this function will NOT throw an exception but return "nil" if it can't parse a string
  def parse(s)
    if s.class != String
      return nil # it's not even a string'
    end
    return_value = 0
    for one_const in s.split('|')
      one_const = one_const.strip()
      if not consts.has_key? one_const
        return nil # at least one "Constant" is unknown to us
      end
      return_value |= consts[one_const]
    end
    return return_value
  end

  def is_parseable(s)
    return !parse(s).nil?
  end

  #
  # Returns an array of constant names that have a value matching "const"
  # and (optionally) a name that matches "filter_regex"
  #
  def select_const_names(const, filter_regex=nil)
    matches = []

    consts.each_pair do |name, value|
      matches << name if value == const
    end

    # Filter matches by name if a filter has been provided
    unless filter_regex.nil?
      matches.reject! do |name|
        name !~ filter_regex
      end
    end

    return matches
  end
end

end; end; end; end; end; end
