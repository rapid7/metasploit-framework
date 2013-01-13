#
# Gems
#
require 'active_support/concern'

# Concerns the module cache maintained by the {Msf::ModuleManager}.
module Msf::ModuleManager::Cache
  extend ActiveSupport::Concern

  # Returns whether the cache is empty
  #
  # @return [true] if the cache has no entries.
  # @return [false] if the cache has any entries.
  def cache_empty?
    module_info_by_path.empty?
  end

  # Forces loading of the module with the given type and module reference name from the cache.
  #
  # @param [String] type the type of the module.
  # @param [String] reference_name the module reference name.
  # @return [false] if a module with the given type and reference name does not exist in the cache.
  # @return (see Msf::Modules::Loader::Base#load_module)
  def load_cached_module(type, reference_name)
    loaded = false

    module_info = self.module_info_by_path.values.find { |inner_info|
      inner_info[:type] == type and inner_info[:reference_name] == reference_name
    }

    if module_info
      parent_path = module_info[:parent_path]

      loaders.each do |loader|
        if loader.loadable?(parent_path)
          type = module_info[:type]
          reference_name = module_info[:reference_name]

          loaded = loader.load_module(parent_path, type, reference_name, :force => true)

          break
        end
      end
    end

    loaded
  end

  # Rebuild the cache for the module set
  #
  # @return [void]
  def refresh_cache_from_module_files(mod = nil)
    if framework_migrated?
      if mod
        framework.db.update_module_details(mod)
      else
        framework.db.update_all_module_details
      end

      refresh_cache_from_database
    end
  end

  # Reset the module cache
  #
  # @return [void]
  def refresh_cache_from_database
    self.module_info_by_path_from_database!
  end

  protected

  # Returns whether the framework migrations have been run already.
  #
  # @return [true] if migrations have been run
  # @return [false] otherwise
  def framework_migrated?
    if framework.db and framework.db.migrated
      true
    else
      false
    end
  end

  # @!attribute [rw] module_info_by_path
  #   @return (see #module_info_by_path_from_database!)
  attr_accessor :module_info_by_path

  # Return a module info from Mdm::ModuleDetails in database.
  #
  # @note Also sets module_set(module_type)[module_reference_name] to Msf::SymbolicModule if it is not already set.
  #
  # @return [Hash{String => Hash{Symbol => Object}}] Maps path (Mdm::ModuleDetail#file) to module information.  Module
  #   information is a Hash derived from Mdm::ModuleDetail.  It includes :modification_time, :parent_path, :type,
  #   :reference_name.
  def module_info_by_path_from_database!
    self.module_info_by_path = {}

    if framework_migrated?
      # TODO record module parent_path in {Mdm::ModuleDetail} so it does not need to be derived from file.
      ::Mdm::ModuleDetail.find(:all).each do |module_detail|
        path = module_detail.file
        type = module_detail.mtype
        reference_name = module_detail.refname

        typed_path = Msf::Modules::Loader::Base.typed_path(type, reference_name)
        escaped_typed_path = Regexp.escape(typed_path)
        parent_path = path.gsub(/#{escaped_typed_path}$/, '')

        module_info_by_path[path] = {
            :reference_name => reference_name,
            :type => type,
            :parent_path => parent_path,
            :modification_time => module_detail.mtime
        }

        typed_module_set = module_set(type)

        # Don't want to trigger as {Msf::ModuleSet#create} so check for
        # key instead of using ||= which would call {Msf::ModuleSet#[]}
        # which would potentially call {Msf::ModuleSet#create}.
        unless typed_module_set.has_key? reference_name
          typed_module_set[reference_name] = Msf::SymbolicModule
        end
      end
    end

    self.module_info_by_path
  end
end
