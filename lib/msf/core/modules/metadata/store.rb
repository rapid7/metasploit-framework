require 'pstore'
require 'msf/core/modules/metadata'

#
# Handles storage of module metadata on disk. A base metadata file is always included - this was added to ensure a much
# better first time user experience as generating the user based metadata file requires 100+ mb at the time of creating
# this module. Subsequent starts of metasploit will load from a user specific metadata file as users potentially load modules
# from other places.
#
module Msf::Modules::Metadata::Store

  BaseMetaDataFile = 'modules_metadata_base.pstore'
  UserMetaDataFile = 'modules_metadata.pstore'

  #
  # Initializes from user store (under ~/.msf4) if it exists. else base file (under $INSTALL_ROOT/db) is copied and loaded.
  #
  def init_store
    load_metadata
  end

  #
  # Update the module meta cache disk store
  #
  def update_store
    @store.transaction do
      @store[:module_metadata] = @module_metadata_cache
    end
  end

  #######
  private
  #######

  def load_metadata
    begin
      retries ||= 0
      configure_user_store
      @store = PStore.new(@path_to_user_metadata)
      @module_metadata_cache = @store.transaction(true) { @store[:module_metadata]}
      validate_data if (!@module_metadata_cache.nil? && @module_metadata_cache.size > 0)
      @module_metadata_cache = {} if @module_metadata_cache.nil?
    rescue
      retries +=1

      # Try to handle the scenario where the file is corrupted
      if (retries < 2 && ::File.exist?(@path_to_user_metadata))
        FileUtils.remove(@path_to_user_metadata, true)
        retry
      else
        @console.print_warning('Unable to load module metadata')
      end
    end

  end

  def validate_data
    size_prior = @module_metadata_cache.size
    @module_metadata_cache.delete_if {|path, module_metadata| !::File.exist?(module_metadata.path)}
    update_store if (size_prior != @module_metadata_cache.size)
  end

  def configure_user_store
    @path_to_user_metadata =  ::File.join(Msf::Config.config_directory, UserMetaDataFile)
    path_to_base_metadata = ::File.join(Msf::Config.install_root, "db", BaseMetaDataFile)

    if (!::File.exist?(path_to_base_metadata))
      wlog("Missing base module metadata file: #{path_to_base_metadata}")
    else
      if (!::File.exist?(@path_to_user_metadata))
        FileUtils.cp(path_to_base_metadata, @path_to_user_metadata)
        dlog('Created user based module store')

       # Update the user based module store if an updated base file is created/pushed
      elsif (::File.mtime(path_to_base_metadata).to_i > ::File.mtime(@path_to_user_metadata).to_i)
        FileUtils.remove(@path_to_user_metadata, true)
        FileUtils.cp(path_to_base_metadata, @path_to_user_metadata)
        dlog('Updated user based module store')
      end
    end
  end

end

