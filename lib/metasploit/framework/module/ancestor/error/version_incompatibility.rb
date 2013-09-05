# Error raised by {Msf::Modules::Namespace#version_compatible!} on {Msf::Modules::Loader::Base#create_namespace_module}
# if the API or Core version does not meet the minimum requirements defined in the RequiredVersions constant in the
# {Msf::Modules::Loader::Base#read_module_content module content}.
class Metasploit::Framework::Module::Ancestor::Error::VersionIncompatibility < Metasploit::Framework::Module::Ancestor::Error::Base
  # @param [Hash{Symbol => Float}] attributes
  # @option attributes [Float] :minimum_api_version The minimum {Msf::Framework::VersionAPI} as defined in
  #   RequiredVersions.
  # @option attributes [Float] :minimum_core_version The minimum {Msf::Framework::VersionCore} as defined in
  #   RequiredVersions.
  def initialize(attributes={})
    @minimum_api_version = attributes[:minimum_api_version]
    @minimum_core_version = attributes[:minimum_core_version]

    message_parts = []
    message_parts << 'version check'

    if minimum_api_version or minimum_core_version
      clause_parts = []

      if minimum_api_version
        clause_parts << "API >= #{minimum_api_version}"
      end

      if minimum_core_version
        clause_parts << "Core >= #{minimum_core_version}"
      end

      clause = clause_parts.join(' and ')
      message_parts << "(requires #{clause})"
    end

    causal_message = message_parts.join(' ')

    super_attributes = {
        :causal_message => causal_message
    }.merge(attributes)

    super(super_attributes)
  end

  # @return [Float] The minimum value of {Msf::Framework::VersionAPI} for the module to be compatible.
  attr_reader :minimum_api_version
  # @return [Float] The minimum value of {Msf::Framework::VersionCore} for the module to be compatible.
  attr_reader :minimum_core_version
  # @return [String] the path to the module that declared the RequiredVersions
  attr_reader :module_path
  # @return [String] the module reference name that declared the RequiredVersions
  attr_reader :module_reference_name
end