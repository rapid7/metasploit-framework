module Octokit
  # GitHub organization class to generate API path urls
  class Organization
    # Get the api path for an organization
    #
    # @param org [String, Integer] GitHub organization login or id
    # @return [String] Organization Api path
    def self.path org
      case org
      when String
        "orgs/#{org}"
      when Integer
        "organizations/#{org}"
      end
    end
  end
end
