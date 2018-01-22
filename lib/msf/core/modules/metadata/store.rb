require 'json'
require 'msf/core/modules/metadata'

#
# Handles storage of module metadata on disk. A base metadata file is always included - this was added to ensure a much
# better first time user experience as generating the user based metadata file requires 100+ mb at the time of creating
# this module. Subsequent starts of metasploit will load from a user specific metadata file as users potentially load modules
# from other places.
#
module Msf::Modules::Metadata::Store

  def initialize
    @update_mutex = Mutex.new
  end

  BaseMetaDataFile = 'modules_metadata_base.json'
  UserMetaDataFile = 'modules_metadata.json'

  #
  # Initializes from user store (under ~/store/.msf4) if it exists. else base file (under $INSTALL_ROOT/db) is copied and loaded.
  #
  def init_store
    load_metadata
  end

  #######
  private
  #######

  #
  # Update the module meta cache disk store
  #
  def update_store
    begin
      @update_mutex.synchronize {
        json_map = @module_metadata_cache.sort.to_h
        File.open(@path_to_user_metadata, "w") do |f|
          f.write(JSON.pretty_generate(json_map))
        end
      }
    rescue => e
      elog("Unable to update metadata store: #{e.message}")
    end
  end

  def load_metadata
    begin
      retries ||= 0
      copied = configure_user_store
      load_cache_from_file_store
      validate_data(copied) if (!@module_metadata_cache.nil? && @module_metadata_cache.size > 0)
      @module_metadata_cache = {} if @module_metadata_cache.nil?
    rescue Exception => e
      retries +=1

      # Try to handle the scenario where the file is corrupted
      if (retries < 2 && ::File.exist?(@path_to_user_metadata))
        elog('Possible corrupt user metadata store, attempting restore')
        FileUtils.remove(@path_to_user_metadata)
        retry
      else
        @console.print_warning('Unable to load module metadata from disk see error log')
        elog("Unable to load module metadata: #{e.message}")
      end
    end

  end

  def validate_data(copied)
    size_prior = @module_metadata_cache.size
    @module_metadata_cache.delete_if {|key, module_metadata| !::File.exist?(module_metadata.path)}

    if (copied)
      @module_metadata_cache.each_value {|module_metadata|
        module_metadata.update_mod_time(::File.mtime(module_metadata.path))
      }
    end

    update_store if (size_prior != @module_metadata_cache.size || copied)
  end

  def configure_user_store
    copied = false
    @path_to_user_metadata = get_user_store
    path_to_base_metadata = ::File.join(Msf::Config.install_root, "db", BaseMetaDataFile)
    user_file_exists = ::File.exist?(@path_to_user_metadata)
    base_file_exists = ::File.exist?(path_to_base_metadata)

    if (!base_file_exists)
      wlog("Missing base module metadata file: #{path_to_base_metadata}")
      return copied if !user_file_exists
    end

    if (!user_file_exists)
      FileUtils.cp(path_to_base_metadata, @path_to_user_metadata)
      copied = true

      dlog('Created user based module store')

     # Update the user based module store if an updated base file is created/pushed
    elsif (::File.mtime(path_to_base_metadata).to_i > ::File.mtime(@path_to_user_metadata).to_i)
      FileUtils.remove(@path_to_user_metadata)
      FileUtils.cp(path_to_base_metadata, @path_to_user_metadata)
      copied = true
      dlog('Updated user based module store')
    end

    return copied
  end

  def get_user_store
    store_dir = ::File.join(Msf::Config.config_directory, "store")
    FileUtils.makedirs(store_dir) if !::File.exist?(store_dir)
    return ::File.join(store_dir, UserMetaDataFile)
  end

  def load_cache_from_file_store
    cache_map = JSON.parse(File.read(@path_to_user_metadata))
    cache_map.each {|k,v|
      begin
        @module_metadata_cache[k] =  Msf::Modules::Metadata::Obj.from_hash(v)
      rescue => e
        elog("Unable to load module metadata object with key: #{k}")
      end
    }
  end

end

