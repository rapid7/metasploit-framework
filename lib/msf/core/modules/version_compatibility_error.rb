class Msf::Modules::VersionCompatibilityError < StandardError
  def initialize(attributes={})
    @minimum_api_version = attributes[:minimum_api_version]
    @minimum_core_version = attributes[:minimum_core_version]

    super("Failed to reload module (#{name}) due to version check " \
          "(requires API:#{minimum_api_version} Core:#{minimum_core_version})")
  end

  attr_reader :minimum_api_version
  attr_reader :minimum_core_version
end