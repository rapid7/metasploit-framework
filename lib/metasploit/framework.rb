#
# Gems
#
# gems must load explicitly any gem declared in gemspec
# @see https://github.com/bundler/bundler/issues/2018#issuecomment-6819359
#

require 'active_support'
require 'bcrypt'
require 'json'
require 'msgpack'
require 'metasploit/credential'
require 'nokogiri'
require 'packetfu'
# railties has not autorequire defined
# rkelly-remix is a fork of rkelly, so it's autorequire is 'rkelly' and not 'rkelly-remix'
require 'rkelly'
require 'robots'
require 'zip'

#
# Project
#

require 'msf/core'

# Top-level namespace that is shared between {Metasploit::Framework
# metasploit-framework} and pro, which uses Metasploit::Pro.
module Metasploit
  # Supports Rails and Rails::Engine like access to metasploit-framework so it
  # works in compatible manner with activerecord's rake tasks and other
  # railties.
  module Framework
    extend ActiveSupport::Autoload

    autoload :Spec
    autoload :ThreadFactoryProvider

    # Returns the root of the metasploit-framework project.  Use in place of
    # `Rails.root`.
    #
    # @return [Pathname]
    def self.root
      unless instance_variable_defined? :@root
        pathname = Pathname.new(__FILE__)
        @root = pathname.parent.parent.parent
      end

      @root
    end
  end
end
