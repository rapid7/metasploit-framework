# -*- coding: binary -*-
#
# Gems
#
require 'active_support/concern'
require 'msf/core/modules/metadata/cache'

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

  # @note path, reference_name, and type must be passed as options because when +class_or_module+ is a payload Module,
  #   those attributes will either not be set or not exist on the module.
  #
  # Updates the in-memory cache so that {#file_changed?} will report +false+ if
  # the module is loaded again.
  #
  # @param class_or_module [Class<Msf::Module>, ::Module] either a module Class
  #   or a payload Module.
  # @param options [Hash{Symbol => String}]
  # @option options [String] :path the path to the file from which
  #   +class_or_module+ was loaded.
  # @option options [String] :reference_name the reference name for
  #   +class_or_module+.
  # @option options [String] :type the module type
  # @return [void]
  # @raise [KeyError] unless +:path+ is given.
  # @raise [KeyError] unless +:reference_name+ is given.
  # @raise [KeyError] unless +:type+ is given.
  def cache_in_memory(class_or_module, options={})
    options.assert_valid_keys(:path, :reference_name, :type)

    path = options.fetch(:path)

    begin
      modification_time = File.mtime(path)
    rescue Errno::ENOENT => error
      log_lines = []
      log_lines << "Could not find the modification of time of #{path}:"
      log_lines << error.class.to_s
      log_lines << error.to_s
      log_lines << "Call stack:"
      log_lines += error.backtrace

      log_message = log_lines.join("\n")
      elog(log_message)
    else
      parent_path = class_or_module.parent.parent_path
      reference_name = options.fetch(:reference_name)
      type = options.fetch(:type)

      module_info_by_path[path] = {
          :modification_time => modification_time,
          :parent_path => parent_path,
          :reference_name => reference_name,
          :type => type
      }
    end
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

      # XXX borked
      loaders.each do |loader|
        if loader.loadable?(parent_path)
          type = module_info[:type]
          reference_name = module_info[:reference_name]

          loaded = loader.load_module(parent_path, type, reference_name, :force => true)

          break if loaded
        end
      end
    end

    loaded
  end

  # @overload refresh_cache_from_module_files
  #   Rebuilds module metadata store and in-memory cache for all modules.
  #
  #   @return [void]
  # @overload refresh_cache_from_module_files(module_class_or_instance)
  #   Rebuilds database and in-memory cache for given module_class_or_instance.
  #
  #   @param (see Msf::DBManager#update_module_details)
  #   @return [void]
  def refresh_cache_from_module_files(module_class_or_instance = nil)
    if module_class_or_instance
      Msf::Modules::Metadata::Cache.instance.refresh_metadata_instance(module_class_or_instance)
    else
      module_sets =
          [
              ['exploit', @framework.exploits],
              ['auxiliary', @framework.auxiliary],
              ['post', @framework.post],
              ['payload', @framework.payloads],
              ['encoder', @framework.encoders],
              ['nop', @framework.nops]
          ]
      Msf::Modules::Metadata::Cache.instance.refresh_metadata(module_sets)
    end
    refresh_cache_from_database(self.module_paths)
  end

  # Refreshes the in-memory cache from the database cache.
  #
  # @return [void]
  def refresh_cache_from_database(allowed_paths=[""])
    self.module_info_by_path_from_database!(allowed_paths)
  end

  protected

  # @!attribute [rw] module_info_by_path
  #   @return (see #module_info_by_path_from_store!)
  attr_accessor :module_info_by_path

  # Return a module info from Msf::Modules::Metadata::Obj.
  #
  # @note Also sets module_set(module_type)[module_reference_name] to Msf::SymbolicModule if it is not already set.
  #
  # @return [Hash{String => Hash{Symbol => Object}}] Maps path (Mdm::Module::Detail#file) to module information.  Module
  #   information is a Hash derived from Mdm::Module::Detail.  It includes :modification_time, :parent_path, :type,
  #   :reference_name.
  def module_info_by_path_from_database!(allowed_paths=[""])
    self.module_info_by_path = {}

    allowed_paths = allowed_paths.map{|x| x + "/"}

    metadata = Msf::Modules::Metadata::Cache.instance.get_metadata
    metadata.each do |module_metadata|
      path = module_metadata.path
      type = module_metadata.type
      reference_name = module_metadata.ref_name

      # Skip cached modules that are not in our allowed load paths
      next if allowed_paths.select{|x| path.index(x) == 0}.empty?

      # The load path is assumed to be the next level above the type directory
      type_dir = File.join('', Mdm::Module::Detail::DIRECTORY_BY_TYPE[type], '')
      parent_path = path.split(type_dir)[0..-2].join(type_dir) # TODO: rewrite

      module_info_by_path[path] = {
          :reference_name => reference_name,
          :type => type,
          :parent_path => parent_path,
          :modification_time => module_metadata.mod_time
      }

      typed_module_set = module_set(type)

      # Don't want to trigger as {Msf::ModuleSet#create} so check for
      # key instead of using ||= which would call {Msf::ModuleSet#[]}
      # which would potentially call {Msf::ModuleSet#create}.
      if typed_module_set
        unless typed_module_set.has_key?(reference_name)
          typed_module_set[reference_name] = Msf::SymbolicModule
        end
      end
    end

    self.module_info_by_path
  end
end
