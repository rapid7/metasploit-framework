require 'singleton'
#
# Core service class that provides storage of module metadata as well as operations on the metadata.
# Note that operations on this metadata are included as separate modules.
#
module Msf
module Modules
module Metadata

class Cache
  include Singleton
  include Msf::Modules::Metadata::Search
  include Msf::Modules::Metadata::Store
  include Msf::Modules::Metadata::Maps
  include Msf::Modules::Metadata::Stats

  #
  # Refreshes cached module metadata as well as updating the store
  #
  def refresh_metadata_instance(module_instance)
    @mutex.synchronize {
      dlog "Refreshing #{module_instance.refname} of type: #{module_instance.type}"
      refresh_metadata_instance_internal(module_instance)
      update_store
    }
  end

  #
  #  Returns the module data cache, but first ensures all the metadata is loaded
  #
  def get_metadata
    @mutex.synchronize {
      wait_for_load
      @module_metadata_cache.values
    }
  end

  def get_module_reference(type:, reference_name:)
    @mutex.synchronize do
      wait_for_load
      @module_metadata_cache["#{type}_#{reference_name}"]
    end
  end
  #
  # Checks for modules loaded that are not a part of the cache and updates the underlying store
  # if there are changes.
  #
  def refresh_metadata(module_sets)
    has_changes = false
    @mutex.synchronize {
      unchanged_module_references = get_unchanged_module_references
      module_sets.each do |mt|
        unchanged_reference_name_set = unchanged_module_references[mt[0]]

        mt[1].keys.sort.each do |mn|
          next if unchanged_reference_name_set.include? mn

          begin
            module_instance = mt[1].create(mn, cache_type: Msf::ModuleManager::Cache::MEMORY)
          rescue Exception => e
            elog "Unable to create module: #{mn}. #{e.message}"
          end

          unless module_instance
            wlog "Removing invalid module reference from cache: #{mn}"
            existed = remove_from_cache(mn)
            if existed
              has_changes = true
            end
            next
          end

          begin
            refresh_metadata_instance_internal(module_instance)
            has_changes = true
          rescue Exception => e
            elog("Error updating module details for #{module_instance.fullname}", error: e)
          end
        end
      end
      if has_changes
        rebuild_type_cache
      end
    }
    if has_changes
      update_store
      clear_maps
      update_stats
    end
  end

  def module_metadata(type)
    @mutex.synchronize do
      wait_for_load
      type_hash = @metadata_type_index[type]
      type_hash ? type_hash.dup : {}
    end
  end

  #######
  private
  #######

  #
  # Returns  a hash(type->set) which references modules that have not changed.
  #
  def get_unchanged_module_references
    skip_reference_name_set_by_module_type = Hash.new { |hash, module_type|
      hash[module_type] = Set.new
    }

    @module_metadata_cache.each_value do |module_metadata|

      unless module_metadata.path && ::File.exist?(module_metadata.path)
        next
      end

      if ::File.mtime(module_metadata.path).to_i != module_metadata.mod_time.to_i
        next
      end

      skip_reference_name_set = skip_reference_name_set_by_module_type[module_metadata.type]
      skip_reference_name_set.add(module_metadata.ref_name)
    end

    return skip_reference_name_set_by_module_type
  end

  def remove_from_cache(module_name)
    old_cache_size = @module_metadata_cache.size
    @module_metadata_cache.delete_if {|_, module_metadata|
      module_metadata.ref_name.eql? module_name
    }

    removed = old_cache_size != @module_metadata_cache.size
    rebuild_type_cache if removed
    removed
  end

  def wait_for_load
    @load_thread.join unless @store_loaded
  end

  def refresh_metadata_instance_internal(module_instance)
    metadata_obj = Obj.new(module_instance)

    # Remove all instances of modules pointing to the same path. This prevents stale data hanging
    # around when modules are incorrectly typed (eg: Auxiliary that should be Exploit)
    had_type_mismatch_deletion = false
    @module_metadata_cache.delete_if {|_, module_metadata|
      is_stale = module_metadata.path.eql?(metadata_obj.path) && module_metadata.type != metadata_obj.type
      had_type_mismatch_deletion = true if is_stale
      is_stale
    }

    cache_key = get_cache_key(module_instance)
    @module_metadata_cache[cache_key] = metadata_obj

    if had_type_mismatch_deletion
      # Type changed - full rebuild needed since we removed entries from other type buckets
      rebuild_type_cache
    else
      # Common case - just update the single entry in the type index
      type_hash = (@metadata_type_index[metadata_obj.type] ||= {})
      type_hash[metadata_obj.ref_name] = metadata_obj
    end
  end

  def get_cache_key(module_instance)
    "#{module_instance.type}_#{module_instance.class.refname}"
  end

  # Rebuild the per-type index from the main cache.
  def rebuild_type_cache
    by_type = {}
    @module_metadata_cache.each_value do |metadata|
      type_hash = (by_type[metadata.type] ||= {})
      type_hash[metadata.ref_name] = metadata
    end
    @metadata_type_index = by_type
  end

  def initialize
    super
    @mutex = Mutex.new
    @module_metadata_cache = {}
    @metadata_type_index = {}
    @store_loaded = false
    @console = Rex::Ui::Text::Output::Stdio.new
    @load_thread = Thread.new {
      init_store
      rebuild_type_cache
      @store_loaded = true
    }
  end
end

end
end
end
