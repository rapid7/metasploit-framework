#
# Standard Library
#

require 'fileutils'

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

    config.paths.add 'data/meterpreter', glob: '**/ext_*'
    config.paths.add 'modules'

    #
    # `initializer`s
    #

    initializer 'metasploit_framework.merge_meterpreter_extensions' do
      Rails.application.railties.engines.each do |engine|
        merge_meterpreter_extensions(engine)
      end

      # The Rails.application itself could have paths['data/meterpreter'], but will not be part of
      # Rails.application.railties.engines because only direct subclasses of `Rails::Engine` are returned.
      merge_meterpreter_extensions(Rails.application)
    end
  end

  #
  # Instance Methods
  #

  private

  # Merges the meterpreter extensions from `engine`'s `paths['data/meterpreter]`.
  #
  # @param engine [Rails::Engine] a Rails engine or application that has meterpreter extensions
  # @return [void]
  # @todo Make metasploit-framework look for meterpreter extension in paths['data/meterpreter'] from the engine instead of copying them.
  def merge_meterpreter_extensions(engine)
    data_meterpreter_paths = engine.paths['data/meterpreter']

    # may be `nil` since 'data/meterpreter' is not part of the core Rails::Engine paths set.
    if data_meterpreter_paths
      source_paths = data_meterpreter_paths.existent
      destination_directory = root.join('data', 'meterpreter').to_path

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