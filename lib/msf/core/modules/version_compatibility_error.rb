# Error raised by {Msf::Modules::Namespace#version_compatible!} on {Msf::Modules::Loader::Base#create_namespace_module}
# if the API or Core version does not meet the minimum requirements defined in the RequiredVersions constant in the
# {Msf::Modules::Loader::Base#read_module_content module content}.
class Msf::Modules::VersionCompatibilityError < StandardError
  # @param [Hash{Symbol => Float}] attributes
  # @option attributes [Float] :minimum_api_version The minimum {Msf::Framework::VersionAPI} as defined in
  #   RequiredVersions.
  # @option attributes [Float] :minimum_core_version The minimum {Msf::Framework::VersionCore} as defined in
  #   RequiredVersions.
  def initialize(attributes={})
    @module_path = attributes[:module_path]
    @module_reference_name = attributes[:module_reference_name]
    @minimum_api_version = attributes[:minimum_api_version]
    @minimum_core_version = attributes[:minimum_core_version]

    super("Failed to reload module (#{module_reference_name} from #{module_path}) due to version check " \
          "(requires API:#{minimum_api_version} Core:#{minimum_core_version})")
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