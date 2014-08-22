# Concern for behavior that all namespace modules that wrap Msf::Modules must support like version checking and
# grabbing the version specific-Metasploit* class.
module Msf::Modules::Namespace
  # Returns the Metasploit(3|2|1) class from the module_evalled content.
  #
  # @note The module content must be module_evalled into this namespace module before the return of
  #   {#metasploit_class} is valid.
  #
  # @return [Msf::Module] if a Metasploit(3|2|1) class exists in this module
  # @return [nil] if such as class is not defined.
  def metasploit_class
    metasploit_class = nil

    ::Msf::Framework::Major.downto(1) do |major|
      # Since we really only care about the deepest namespace, we don't
      # need to look for parents' constants. However, the "inherit"
      # parameter for const_defined? only exists after 1.9. If we ever
      # drop 1.8 support, we can save a few cycles here by passing false
      # here.
      if const_defined?("Metasploit#{major}")
        metasploit_class = const_get("Metasploit#{major}")

        break
      end
    end

    metasploit_class
  end

  def metasploit_class!(module_path, module_reference_name)
    metasploit_class = self.metasploit_class

    unless metasploit_class
      raise Msf::Modules::MetasploitClassCompatibilityError.new(
                :module_path => module_path,
                :module_reference_name => module_reference_name
            )
    end

    metasploit_class
  end

  # Raises an error unless {Msf::Framework::VersionCore} and {Msf::Framework::VersionAPI} meet the minimum required
  # versions defined in RequiredVersions in the module content.
  #
  # @note The module content must be module_evalled into this namespace module using module_eval_with_lexical_scope
  #   before calling {#version_compatible!} is valid.
  #
  # @param [String] module_path Path from where the module was read.
  # @param [String] module_reference_name The canonical name for the module.
  # @raise [Msf::Modules::VersionCompatibilityError] if RequiredVersion[0] > Msf::Framework::VersionCore or
  #   RequiredVersion[1] > Msf::Framework::VersionApi
  # @return [void]
  def version_compatible!(module_path, module_reference_name)
    if const_defined?(:RequiredVersions)
      required_versions = const_get(:RequiredVersions)
      minimum_core_version = required_versions[0]
      minimum_api_version = required_versions[1]

      if (minimum_core_version > ::Msf::Framework::VersionCore or
          minimum_api_version > ::Msf::Framework::VersionAPI)
        raise Msf::Modules::VersionCompatibilityError.new(
                  :module_path => module_path,
                  :module_reference_name => module_reference_name,
                  :minimum_api_version => minimum_api_version,
                  :minimum_core_version => minimum_core_version
              )
      end
    end
  end
end

