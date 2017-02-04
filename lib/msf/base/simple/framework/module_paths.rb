# -*- coding: binary -*-
module Msf
  module Simple
    module Framework
      module ModulePaths
        # Initialize the module paths
        #
        # @return [void]
        def init_module_paths(opts={})
          if @module_paths_inited
            fail "Module paths already initialized.  To add more module paths call `modules.add_module_path`"
            return
          end

          allowed_module_paths = []
          extract_engine_module_paths(Rails.application).each do |path|
            allowed_module_paths << path
          end

          if Msf::Config.user_module_directory
            allowed_module_paths << Msf::Config.user_module_directory
          end

          ::Rails::Engine.subclasses.map(&:instance).each do |engine|
            extract_engine_module_paths(engine).each do |path|
              allowed_module_paths << path
            end
          end

          # If additional module paths have been defined globally, then load them.
          # They should be separated by semi-colons.
          self.datastore['MsfModulePaths'].to_s.split(";").each do |path|
            allowed_module_paths << path
          end

          # If the caller had additional paths to search, load them.
          # They should be separated by semi-colons.
          opts.delete(:module_paths).to_s.split(";").each do |path|
            allowed_module_paths << path
          end

          # Remove any duplicate paths
          allowed_module_paths.uniq!

          # Update the module cache from the database
          self.modules.refresh_cache_from_database(allowed_module_paths)

          # Load each of the module paths
          allowed_module_paths.each do |path|
            self.modules.add_module_path(path, opts)
          end

          @module_paths_inited = true
        end

        private

        # Extract directories `engine.paths['modules']` from `engine`.
        #
        # @param engine [Rails::Engine] a rails engine or application
        # @return [Array<String>] The list of module paths to load
        def extract_engine_module_paths(engine)
          engine.paths['modules'] ? engine.paths['modules'].existent_directories : []
        end

      end
    end
  end
end
