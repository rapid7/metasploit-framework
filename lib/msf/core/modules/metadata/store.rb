require 'json'
require 'parallel'
require 'zlib'

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

  # This method uses a per-file CRC32 cache to avoid recalculating checksums for files that have not changed.
  # It loads the cache, checks each file's mtime and size, and only recalculates the CRC32 if needed.
  #
  # @return [Boolean] True if the current checksum matches the cached one
  def self.valid_checksum?
    current_checksum = get_current_checksum

    get_store_cache_path
    ensure_cache_file_exists(current_checksum)

    cached_sha = get_cached_checksum

    checksums_match?(current_checksum, cached_sha)
  end

  # Calculate the current checksum for all module and library files
  # This calculates checksums for each file, caches them, and then
  # generates an overall checksum from the individual file checksums.
  #
  # @return [String] The current overall checksum
  def self.get_current_checksum
    files = collect_files_to_check
    per_file_cache_file = get_per_file_cache_path
    per_file_cache = load_per_file_cache(per_file_cache_file)

    file_crc32s_with_metadata = calculate_file_checksums(files, per_file_cache)

    updated_cache = file_crc32s_with_metadata.to_h
    file_crc32s = file_crc32s_with_metadata.map { |_, meta| meta['crc32'] }

    save_per_file_cache(per_file_cache_file, updated_cache)

    calculate_overall_checksum(file_crc32s)
  end

  # Compare the current checksum with the cached checksum
  # @param [String] current_checksum The calculated checksum for the current state
  # @param [String] cached_checksum The checksum retrieved from cache
  # @return [Boolean] True if checksums match, false otherwise
  def self.checksums_match?(current_checksum, cached_checksum)
    current_checksum == cached_checksum
  end

  # Calculate the overall checksum from individual file checksums
  # @param [Array<Integer>] file_crc32s Array of individual file CRC32 values
  # @return [String] The hexadecimal representation of the overall CRC32
  def self.calculate_overall_checksum(file_crc32s)
    Zlib.crc32(file_crc32s.join).to_s(16)
  end

  # Collect all files that need to be checked for checksums
  # @return [Array<String>] List of file paths
  def self.collect_files_to_check
    # Define the directories to scan for files
    modules_dir = File.join(Msf::Config.install_root, 'modules', '**', '*')
    local_modules_dir = File.join(Msf::Config.user_module_directory, '**', '*')
    lib_dir = File.join(Msf::Config.install_root, 'lib', '**', '*')
    # Gather all files from the specified directories
    Dir.glob([modules_dir, lib_dir, local_modules_dir]).select { |f| File.file?(f) }.sort
  end

  # Calculate checksums for all files, using the cache when possible
  # @param [Array<String>] files List of file paths to check
  # @param [Hash] cache Current cache data
  # @return [Array<Array>] Array of [file_path, metadata] pairs
  def self.calculate_file_checksums(files, cache)
    Parallel.map(files, in_threads: Etc.nprocessors * 2) do |file|
      # Get file metadata (size and last modified time)
      file_metadata = File.stat(file)
      cache_entry = cache[file]
      # Use cached CRC32 if mtime and size match, otherwise recalculate
      if cache_entry && cache_entry['mtime'] == file_metadata.mtime.to_i && cache_entry['size'] == file_metadata.size
        crc32 = cache_entry['crc32']
      else
        crc32 = File.open(file, 'rb') { |fd| Zlib.crc32(fd.read) }
      end
      # Return file and its metadata for later aggregation
      [file, {
        'crc32' => crc32,
        'mtime' => file_metadata.mtime.to_i,
        'size' => file_metadata.size
      }]
    end
  end

  # Get the path to the per-file cache
  # @return [String] Path to the per-file cache
  def self.get_per_file_cache_path
    File.join(Msf::Config.config_directory, 'store', 'per_file_metadata_cache.json')
  end

  # Get the path to the cache store file
  # @return [String] Path to the cache store file
  def self.get_store_cache_path
    File.join(Msf::Config.config_directory, "store", CacheMetaDataFile)
  end

  # Get the path to the DB cache file
  # @return [String] Path to the DB cache file
  def self.get_db_cache_path
    File.join(Msf::Config.install_root, "db", CacheMetaDataFile)
  end

  # Load the per-file cache from disk
  # @param [String] cache_file Path to the cache file
  # @return [Hash] The loaded cache or an empty hash if the file doesn't exist
  def self.load_per_file_cache(cache_file)
    File.exist?(cache_file) ? JSON.parse(File.read(cache_file)) : {}
  end

  # Save the updated per-file cache to disk
  # @param [String] cache_file Path to the cache file
  # @param [Hash] updated_cache The cache data to save
  # @return [void]
  def self.save_per_file_cache(cache_file, updated_cache)
    # Ensure the directory for the cache file exists before writing
    FileUtils.mkdir_p(File.dirname(cache_file))
    # Save the updated per-file cache to disk
    File.write(cache_file, JSON.pretty_generate(updated_cache))
  end

  # Create or update a cache file with the given checksum
  # @param [String] file_path Path to the cache file
  # @param [String] checksum The checksum to store
  # @return [void]
  def self.create_or_update_cache_file(file_path, checksum)
    # Ensure directory exists
    FileUtils.mkdir_p(File.dirname(file_path))

    if File.exist?(file_path)
      # Update existing file
      cache_content = JSON.parse(File.read(file_path))
      cache_content['checksum']['crc32'] = checksum
    else
      # Create new file
      cache_content = {
        "checksum" => {
          "crc32" => checksum
        }
      }
    end

    File.write(file_path, JSON.pretty_generate(cache_content))
  end

  # Ensure the db cache file exists, creating it if necessary
  # @param [String] current_checksum The current checksum to use if creating a new cache file
  # @return [void]
  def self.ensure_cache_file_exists(current_checksum)
    # Path to the DB cache file
    cache_db_path = get_db_cache_path

    # Only create the db cache file if it doesn't exist
    # The user's cache file (~/.msf4/store/cache_metadata_base.json) should only be created when changes are made
    unless File.exist?(cache_db_path)
      # Ensure directory exists
      FileUtils.mkdir_p(File.dirname(cache_db_path))
      cache_content = {
        "checksum" => {
          "crc32" => current_checksum
        }
      }
      File.write(cache_db_path, JSON.pretty_generate(cache_content))
    end
  end

  # Get the cached checksum value without creating any new files
  # @return [String, nil] The cached checksum value or nil if no cache exists
  def self.get_cached_checksum
    cache_store_path = get_store_cache_path
    cache_db_path = get_db_cache_path

    # First try user's cache file
    if File.exist?(cache_store_path)
      cache_content = JSON.parse(File.read(cache_store_path))
      return cache_content.dig('checksum', 'crc32')
    end

    # Fall back to db cache file
    if File.exist?(cache_db_path)
      cache_content = JSON.parse(File.read(cache_db_path))
      return cache_content.dig('checksum', 'crc32')
    end

    # If neither exists, return nil to trigger a cache rebuild
    # This allows the build process to work with neither file present
    nil
  end

  # Update the cache checksum file with the current crc32 checksum of the module paths.
  #
  # @param [String] current_checksum The current checksum to store in the cache
  # @return [void]
  def self.update_cache_checksum(current_checksum)
    cache_store_path = get_store_cache_path
    cache_db_path = get_db_cache_path

    if File.exist?(cache_store_path)
      # Update the existing user cache file
      create_or_update_cache_file(cache_store_path, current_checksum)
    elsif File.exist?(cache_db_path)
      # Copy the DB cache file to the user's directory and update it
      FileUtils.cp(cache_db_path, cache_store_path)
      create_or_update_cache_file(cache_store_path, current_checksum)
    else
      # Create a new cache file if neither exists
      create_or_update_cache_file(cache_store_path, current_checksum)
    end
  end
end
