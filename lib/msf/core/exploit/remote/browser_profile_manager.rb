module Msf
  module Exploit::Remote::BrowserProfileManager

    # @overload browser_profile_prefix
    #  Sets the profile prefix to retrieve or load target information.
    def browser_profile_prefix
      raise NoMethodError, "A mixin that's using BrowserProfileManager should define browser_profile_prefix"
    end

    # Storage backend for browser profiles
    #
    # @return [Hash]
    def browser_profile
      framework.browser_profiles[browser_profile_prefix] ||= {}
      framework.browser_profiles[browser_profile_prefix]
    end

    # Storage backend for browser profiles
    #
    def clear_browser_profiles
      framework.browser_profiles.delete(browser_profile_prefix)
    end

  end
end
