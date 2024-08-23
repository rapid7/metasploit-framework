#
# Standard Library
#

require 'fileutils'

#
# Metasploit gem engines
#

require 'metasploit/model/engine'
require 'metasploit/concern/engine'
require 'metasploit/framework/require'
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
      ::Encoding.default_external = encoding
      ::Encoding.default_internal = encoding
    end

    config.root = Msf::Config::install_root
    config.paths.add 'app/models', autoload: true
    config.paths.add 'app/concerns', autoload: true
    config.paths.add 'data/meterpreter', glob: '**/ext_*'
    config.paths.add 'modules'

    config.active_support.deprecation = :stderr

    # @see https://github.com/rapid7/metasploit_data_models/blob/54a17149d5ccd0830db742d14c4987b48399ceb7/lib/metasploit_data_models/yaml.rb#L10
    # @see https://github.com/rapid7/metasploit_data_models/blob/54a17149d5ccd0830db742d14c4987b48399ceb7/lib/metasploit_data_models/base64_serializer.rb#L28-L31
    ActiveRecord.yaml_column_permitted_classes = (ActiveRecord.yaml_column_permitted_classes + MetasploitDataModels::YAML::PERMITTED_CLASSES).uniq

    #
    # `initializer`s
    #


  end

end
