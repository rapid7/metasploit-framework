#
# Standard Library
#

require 'fileutils'

#
# Metasploit gem engines
#

require 'metasploit/model/engine'
require 'metasploit/concern/engine'
Metasploit::Framework::Require.optionally_require_metasploit_db_gem_engines

# `Rails::Engine` behavior common to both {Metasploit::Framework::Application} and {Metasploit::Framework::Engine}.
module Metasploit::Framework::CommonEngine
  extend ActiveSupport::Concern

  included do
    #
    # config
    #

    # Force binary encoding to remove necessity to set external and internal encoding when construct Strings from
    # from files.  Socket#read always returns a String in ASCII-8bit encoding
    #
    # @see http://rubydoc.info/stdlib/core/IO:read
    config.before_initialize do
      encoding = 'binary'
      Encoding.default_external = encoding
      Encoding.default_internal = encoding
    end

    config.root = Msf::Config::install_root
    config.paths.add 'app/concerns', autoload: true
    config.paths.add 'data/meterpreter', glob: '**/ext_*'
    config.paths.add 'modules'

    config.active_support.deprecation = :stderr

    #
    # `initializer`s
    #


  end

end
