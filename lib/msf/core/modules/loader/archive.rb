require 'msf/core/modules/loader/base'

# Concerns loading modules form fastlib archives
class Msf::Modules::Loader::Archive < Msf::Modules::Loader::Base
  #
  # CONSTANTS
  #

  # The extension for Fastlib archives.
  ARCHIVE_EXTENSION = '.fastlib'

  # Returns true if the path is a Fastlib archive.
  #
  # @param (see Msf::Modules::Loader::Base#loadable?)
  # @return [true] if path has the {ARCHIVE_EXTENSION} extname.
  # @return [false] otherwise
  def loadable?(path)
    if File.extname(path) == ARCHIVE_EXTENSION
      true
    else
      false
    end
  end

  protected

  # Yields the module_reference_name for each module file in the Fastlib archive at path.
  #
  # @param path [String] The path to the Fastlib archive file.
  # @param opts [Hash] Additional options
  # @yield (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @yieldparam (see Msf::Modules::Loader::Base#each_module_reference_name)
  # @return (see Msf::Modules::Loader::Base#each_module_reference_name)
  def each_module_reference_name(path, opts={})
    whitelist = opts[:whitelist] || []
    entries = ::FastLib.list(path)

    entries.each do |entry|
      if entry.include?('.svn/')
        next
      end

      type = entry.split('/', 2)[0]
      type = type.singularize

      unless module_manager.type_enabled?(type)
        next
      end

      if whitelist.empty?

        if module_path?(entry)
          # The module_reference_name doesn't have a file extension
          module_reference_name = module_reference_name_from_path(entry)

          yield path, type, module_reference_name
        end
      else
        whitelist.each do |pattern|
          if entry =~ pattern
            yield path, type, module_reference_name
          else
            next
          end
        end
      end
    end
  end

  # Returns the path to the module inside the Fastlib archive.  The path to the archive is separated from the path to
  # the file inside the archive by '::'.
  #
  # @param (see Msf::Modules::Loader::Base#module_path)
  # @return [String] Path to module file inside the Fastlib archive.
  def module_path(parent_path, type, module_reference_name)
    file_path = typed_path(type, module_reference_name)
    module_path = "#{parent_path}::#{file_path}"

    module_path
  end

  # Loads the module content from the Fastlib archive.
  #
  # @return (see Msf::Modules::Loader::Base#read_module_content)
  def read_module_content(path, type, module_reference_name)
    file_path = typed_path(type, module_reference_name)

    ::FastLib.load(path, file_path)
  end
end