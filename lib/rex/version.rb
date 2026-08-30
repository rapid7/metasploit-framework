# rubocop:disable Lint/DeprecatedGemVersion
class Rex::Version < Gem::Version

  def initialize(version)
    if version.nil?
      # Rubygems 4 is deprecating `nil` as a valid version number
      # Currently it is the equivalent of a `0` so we set that here to keep the same functionality
      version = 0
    end
    super version
  end
end
# rubocop:enable Lint/DeprecatedGemVersion
