# Concerns loading modules form fastlib archives
class Metasploit::Framework::Module::Path::Loader::Archive < Metasploit::Framework::Module::Path::Loader::Base
  # Returns true if the path is a Fastlib archive.
  #
  # @param (see Msf::Modules::Loader::Base#loadable?)
  # @return [true] if path is an archive file.
  # @return [false] otherwise
  def loadable?(module_path)
		module_path.archive?
  end

  protected

  # Yields each `Metasploit::Model::Ancestor` in the module path that has
	# changed or all `Metasploit::Model::Ancestor` if `:force => true`.
  #
  # @param (see Metasploit::Framework::Module::Path::Loader::Base#each_module_ancestor)
	# @option (see Metasploit::Framework::Module::Path::Loader::Base#each_module_ancestor)
  # @yield (see Msf::Modules::Loader::Base#each_module_ancestor)
	# @yieldparam (see Msf::Modules::Loader::Base#each_module_ancestor)
	# @yieldreturn (see Msf::Modules::Loader::Base#each_module_ancestor)
  # @return (see Msf::Modules::Loader::Base#each_module_ancestor)
  def each_module_ancestor(module_path, options={})
    entries = ::FastLib.list(module_path.real_path)

    entries.each do |entry|
			real_path = File.join(module_path.real_path, entry)
			ancestor = module_path.module_ancestor_from_real_path(real_path, options)

			if ancestor && module_type_enabled?(ancestor.module_type)
				yield ancestor
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