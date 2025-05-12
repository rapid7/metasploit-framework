# -*- coding: binary -*-

# Concerns loading executables from a directory as modules
class Msf::Modules::Loader::Executable < Msf::Modules::Loader::Base
  # Returns true if the path is a directory
  #
  # @param (see Msf::Modules::Loader::Base#loadable?)
  # @return [true] if path is a directory
  # @return [false] otherwise
  def loadable?(path)
    File.directory?(path)
  end

  # @param [String] parent_path Root directory to load modules from
  # @param [String] type Such as auxiliary, exploit, etc
  # @param [String] module_reference_name The module reference name, without the type prefix
  # @param [nil,Msf::Modules::Metadata::Obj] cached_metadata
  # @return [Boolean] True this loader can load the module, false otherwise
  def loadable_module?(parent_path, type, module_reference_name, cached_metadata: nil)
    full_path = cached_metadata&.path || module_path(parent_path, type, module_reference_name)
    script_path?(full_path)
  end

  protected

  def read_script_env_runtime(full_path)
    # Extract the runtime from the first line of the script, i.e.
    #   #!/usr/bin/env python
    #   //usr/bin/env go run "$0" "$@"; exit "$?"
    first_line = File.open(full_path, 'rb') { |f| f.gets }
    first_line.to_s[%r{\A(?:#!|/)/usr/bin/env\s+(\w+)}, 1]
  end

  # @param [String] full_path The full path to the module file.
  # @return [Boolean] True if the script's required runtime is available on the host, false otherwise
  def script_runtime_available?(full_path)
    return false unless script_path?(full_path)

    # Modules currently use /usr/bin/env - in the future absolute paths may need to be supported
    script_runtime = read_script_env_runtime(full_path)
    return !!Rex::FileUtils.find_full_path(script_runtime) if script_runtime

    # If the script runtime isn't known, we assume the script is executable
    true
  end

  # Yields the module_reference_name for each module file found under the directory path.
  #
  # @param [String] path The path to the directory.
  # @param [Hash] opts Input Hash.
  # @yield (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @yieldparam [String] path The path to the directory.
  # @yieldparam [String] type The type correlated with the directory under path.
  # @yieldparam module_reference_name (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @return (see Msf::Modules::Loader::Base#each_module_reference_name)
  def each_module_reference_name(path, opts={})
    whitelist = opts[:whitelist] || []
    ::Dir.foreach(path) do |entry|
      full_entry_path = ::File.join(path, entry)
      type = entry.singularize

      unless ::File.directory?(full_entry_path) && module_manager.type_enabled?(type)
        next
      end

      full_entry_pathname = Pathname.new(full_entry_path)

      # Try to load modules from all the files in the supplied path
      Rex::Find.find(full_entry_path) do |entry_descendant_path|
        # Assume that all modules are scripts for now, workaround
        # filesystems where all files are labeled as executable.
        if script_path?(entry_descendant_path)
          entry_descendant_pathname = Pathname.new(entry_descendant_path)
          relative_entry_descendant_pathname = entry_descendant_pathname.relative_path_from(full_entry_pathname)
          relative_entry_descendant_path = relative_entry_descendant_pathname.to_s
          next if File::basename(relative_entry_descendant_path).start_with?('example')
          # The module_reference_name doesn't have a file extension
          module_reference_name = File.join(File.dirname(relative_entry_descendant_path), File.basename(relative_entry_descendant_path, '.*'))

          yield path, type, module_reference_name
        end
      end
    end
  end

  # Returns the full path to the module file on disk.
  #
  # @param (see Msf::Modules::Loader::Base#module_path)
  # @return [String] Path to module file on disk.
  def module_path(parent_path, type, module_reference_name)
    # The extension is lost on loading, hit the disk to recover :(
    partial_path = File.join(DIRECTORY_BY_TYPE[type], module_reference_name)
    full_path = File.join(parent_path, partial_path)

    Rex::Find.find(File.dirname(full_path)) do |mod|
      if File.basename(full_path, '.*') == File.basename(mod, '.*')
        return File.join(File.dirname(full_path), File.basename(mod))
      end
    end

    ''
  end

  # Loads the module content from the on disk file.
  #
  # @param (see Msf::Modules::Loader::Base#read_module_content)
  # @return (see Msf::Modules::Loader::Base#read_module_content)
  def read_module_content(parent_path, type, module_reference_name)
    full_path = module_path(parent_path, type, module_reference_name)

    read_module_content_from_path(full_path)
  end

  # Loads the module content from the on disk file.
  #
  # @param (see Msf::Modules::Loader::Base#read_module_content_from_path)
  # @return (see Msf::Modules::Loader::Base#read_module_content_from_path)
  def read_module_content_from_path(full_path)
    unless script_path?(full_path)
      load_error(full_path, Errno::ENOENT.new)
      return ''
    end
    unless script_runtime_available?(full_path)
      load_error(full_path, RuntimeError.new("Unable to load module as the following runtime was not found on the path: #{read_script_env_runtime(full_path)}"))
      return ''
    end

    begin
      content = Msf::Modules::External::Shim.generate(full_path, @module_manager.framework)
      if content
        return content
      else
        elog "Unable to load module #{full_path}, unknown module type"
        return ''
      end
    rescue LoadError => e
      load_error(full_path, e)
      return ''
    rescue ::Exception => e
      elog("Unable to load module #{full_path}", error: e)
      # XXX migrate this to a full load_error when we can tell the user why the
      # module did not load and/or how to resolve it.
      # load_error(full_path, e)
      ''
    end
  end
end
