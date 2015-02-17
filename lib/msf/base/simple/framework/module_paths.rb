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
          else
            # Ensure the module cache is accurate
            self.modules.refresh_cache_from_database

            add_engine_module_paths(Rails.application, opts)

            Rails.application.railties.engines.each do |engine|
              add_engine_module_paths(engine, opts)
            end

            # Initialize the user module search path
            if (Msf::Config.user_module_directory)
              self.modules.add_module_path(Msf::Config.user_module_directory, opts)
            end

            # If additional module paths have been defined globally, then load them.
            # They should be separated by semi-colons.
            if self.datastore['MsfModulePaths']
              self.datastore['MsfModulePaths'].split(";").each { |path|
                self.modules.add_module_path(path, opts)
              }
            end

            @module_paths_inited = true
          end
        end

        private

        # Add directories `engine.paths['modules']` from `engine`.
        #
        # @param engine [Rails::Engine] a rails engine or application
        # @param options [Hash] options for {Msf::ModuleManager::ModulePaths#add_module_paths}
        # @return [void]
        def add_engine_module_paths(engine, options={})
          modules_paths = engine.paths['modules']

          if modules_paths
            modules_directories = modules_paths.existent_directories

            modules_directories.each do |modules_directory|
              modules.add_module_path(modules_directory, options)
            end
          end
        end
      end
    end
  end
end