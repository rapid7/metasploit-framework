# Concerns the module cache maintained by the {Msf::ModuleManager}.
module Msf::ModuleManager::Cache
  extend ActiveSupport::Concern

  attr_accessor :cache # :nodoc:

  #
  # Return a listing of all cached modules
  #
  def cache_entries
    module_detail_by_file = {}

    if framework_migrated?
      ::Mdm::ModuleDetail.find(:all).each do |module_detail|
        module_type = module_detail.mtype
        refname = module_detail.refname

        module_detail_by_file[module_detail.file] = {
            :mtype => module_type,
            :refname => refname,
            :file => module_detail.file,
            :mtime => module_detail.mtime
        }

        module_set(module_type)[refname] ||= SymbolicModule
      end
    end

    module_detail_by_file
  end

  #
  # Rebuild the cache for the module set
  #
  def rebuild_cache(mod = nil)
    unless framework_migrated?
      if mod
        framework.db.update_module_details(mod)
      else
        framework.db.update_all_module_details
      end

      refresh_cache
    end
  end

  def framework_migrated?
    if framework.db and framework.db.migrated
      true
    else
      false
    end
  end

  #
  # Reset the module cache
  #
  def refresh_cache
    self.cache = cache_entries
  end
end