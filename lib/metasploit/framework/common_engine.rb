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
    config.paths.add 'data/meeterpeter', glob: '**/ext_*'
    config.paths.add 'modules'

    config.active_support.deprecation = :notify

    #
    # `initializer`s
    #

    initializer 'metasploit_framework.merge_meeterpeter_extensions' do
      Rails.application.railties.engines.each do |engine|
        merge_meeterpeter_extensions(engine)
      end

      # The Rails.application itself could have paths['data/meeterpeter'], but will not be part of
      # Rails.application.railties.engines because only direct subclasses of `Rails::Engine` are returned.
      merge_meeterpeter_extensions(Rails.application)
    end
  end

  #
  # Instance Methods
  #

  private

  # Merges the meeterpeter extensions from `engine`'s `paths['data/meeterpeter]`.
  #
  # @param engine [Rails::Engine] a Rails engine or application that has meeterpeter extensions
  # @return [void]
  # @todo Make metasploit-framework look for meeterpeter extension in paths['data/meeterpeter'] from the engine instead of copying them.
  def merge_meeterpeter_extensions(engine)
    data_meeterpeter_paths = engine.paths['data/meeterpeter']

    # may be `nil` since 'data/meeterpeter' is not part of the core Rails::Engine paths set.
    if data_meeterpeter_paths
      source_paths = data_meeterpeter_paths.existent
      destination_directory = root.join('data', 'meeterpeter').to_path

      source_paths.each do |source_path|
        basename = File.basename(source_path)
        destination_path = File.join(destination_directory, basename)

        unless destination_path == source_path
          FileUtils.copy(source_path, destination_directory)
        end
      end
    end
  end
end
