require 'json'
require 'digest/md5'
require 'parallel'

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
  CacheMetaDataFile = 'cache_metadata_base.json'

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
      elog('Unable to update metadata store', error: e)
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
        elog('Unable to load module metadata', error: e)
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
        elog("Unable to load module metadata object with key: #{k}", error: e)
      end
    }
  end

  # This method uses a per-file MD5 cache to avoid recalculating checksums for files that have not changed.
  # It loads the cache, checks each file's mtime and size, and only recalculates the MD5 if needed.
  # The overall checksum is a hash of all per-file MD5s concatenated together.
  #
  # @return [Boolean]
  def self.valid_checksum?
    # Define the directories to scan for files
    modules_dir = File.join(Msf::Config.install_root, 'modules', '**', '*')
    local_modules_dir = File.join(Msf::Config.user_module_directory, '**', '*')
    lib_dir = File.join(Msf::Config.install_root, 'lib', '**', '*')
    # Gather all files from the specified directories
    files = Dir.glob([modules_dir, lib_dir, local_modules_dir]).select { |f| File.file?(f) }.sort

    # Path to the per-file MD5 cache
    cache_file = File.join(Msf::Config.config_directory, 'store', 'md5_cache.json')
    # Load the cache if it exists, otherwise start with an empty hash
    per_file_cache = File.exist?(cache_file) ? JSON.parse(File.read(cache_file)) : {}

    # Calculate per-file MD5s in parallel, only recalculating if mtime/size changed
    file_md5s_with_metadata = Parallel.map(files, in_threads: Etc.nprocessors * 2) do |file|
      # Get file metadata (size and last modified time)
      file_metadata = File.stat(file)
      cache_entry = per_file_cache[file]
      # Use cached MD5 if mtime and size match, otherwise recalculate
      if cache_entry && cache_entry['mtime'] == file_metadata.mtime.to_i && cache_entry['size'] == file_metadata.size
        md5 = cache_entry['md5']
      else
        md5 = Digest::MD5.file(file).hexdigest
      end
      # Return file and its metadata for later aggregation
      [file, {
        'md5' => md5,
        'mtime' => file_metadata.mtime.to_i,
        'size' => file_metadata.size
      }]
    end

    # Build the updated_cache hash from the results
    updated_cache = file_md5s_with_metadata.to_h
    file_md5s = file_md5s_with_metadata.map { |_, meta| meta['md5'] }

    # Ensure the directory for the cache file exists before writing
    FileUtils.mkdir_p(File.dirname(cache_file))
    # Save the updated per-file cache to disk
    File.write(cache_file, JSON.pretty_generate(updated_cache))

    # Combine all per-file MD5s into a single string and hash it for the overall checksum
    overall_md5 = Digest::MD5.hexdigest(file_md5s.join)
    @current_checksum = overall_md5

    @cache_store_path = File.join(Msf::Config.config_directory, "store", CacheMetaDataFile)
    cache_db_path = File.join(Msf::Config.install_root, "db", CacheMetaDataFile)

    # If the cache file does not exist, copy the db cache and update the md5 value
    unless File.exist?(@cache_store_path)
      FileUtils.mkdir_p(File.dirname(@cache_store_path))
      FileUtils.cp(cache_db_path, @cache_store_path)
      # Update the md5 value in the copied file
      cache_content = JSON.parse(File.read(@cache_store_path))
      cache_content['checksum'] ||= {}
      cache_content['checksum']['md5'] = @current_checksum
      File.write(@cache_store_path, JSON.pretty_generate(cache_content))
    end

    cache_content = JSON.parse(File.read(@cache_store_path))
    cached_sha = cache_content.dig('checksum', 'md5')

    # Return true if the current checksum matches the cached one, otherwise return false
    @current_checksum == cached_sha
  end

  # Update the cache checksum file with the current md5 checksum of the module paths.
  #
  # @return [Integer]
  def self.update_cache_checksum
    updated_cache_content = { 'checksum' => { 'md5' => @current_checksum } }
    FileUtils.rm_f(@cache_store_path)
    File.write(@cache_store_path, JSON.pretty_generate(updated_cache_content))
  end
end
