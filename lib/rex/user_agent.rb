# -*- coding: binary -*-

#
# A helper module for using and referencing coming user agent strings.
#
module Rex::UserAgent

  #
  # Taken from https://www.whatismybrowser.com/guides/the-latest-user-agent/
  #
  COMMON_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', # Chrome Windows
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', # Chrome MacOS

    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86', # Edge Windows

    'Mozilla/5.0 (iPad; CPU OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1', # Safari iPad
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15', # Safari MacOS

    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0', # Firefox Windows
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:133.0) Gecko/20100101 Firefox/133.0' # Firefox MacOS
  ]

  #
  # A randomly-selected agent that will be consistent for the duration of metasploit running
  #
  def self.session_agent
    if @@session_agent
      @@session_agent
    else
      @@session_agent = self.random
    end
  end

  @@session_agent = nil

  #
  # Pick a random agent from the common agent list.
  #
  def self.random
    COMMON_AGENTS.sample
  end

  #
  # Choose the agent with the shortest string (for use in payloads)
  #
  def self.shortest
    @@shortest_agent ||= COMMON_AGENTS.min { |a, b| a.size <=> b.size }
  end

  #
  # Choose the most frequent user agent
  #
  def self.most_common
    COMMON_AGENTS[0]
  end


  #
  # Generate a random user-agent
  #
  def self.randomagent
    is_kernel_version = "#{rs_version}.#{rs_version}.#{rs_version}"
    is_browser_version = "#{rs_version}.#{rs_version}.#{rs_version}"
    "#{rs_mozilla_version}#{rs_platform} #{rs_browser_kernel}/#{is_kernel_version} #{rs_is_browser}/#{is_browser_version}"
  end


  #
  # Generate a random Mozilla version
  #
  def self.rs_mozilla_version
    random_number = rand(4..200)
    "Mozilla/#{random_number}.0 "
  end

  # Generate random platform information
  def self.rs_platform
    operating_systems = ["Windows", "Mac", "Linux", "Android", "Windows NT 6.1, OpenHarmony", "Phone", "HarmonyOS"]
    random_os = operating_systems.sample
    "(#{random_os}; #{rs_platform_os_bit}; #{rs_browser}; #{rs_encryption_u}; #{rs_language})"
  end

  # Generate random language
  def self.rs_language
    languages = [
      "zu", "ji", "xh", "cy", "vi", "ve", "ur", "ua", "tr", "tn", "ts", "th", "sv-fi", "sv", "es-ve", "es-uy", "es", "es-pr", "es-pe", "es-py", "es-pa",
      "es-ni", "es-mx", "es-hn", "es-gt", "es-sv", "es-ec", "es-do", "es-cr", "es-co", "es-cl", "es-bo", "es-ar", "sb", "sl", "sk", "sr", "ru-md", "ru", "ro-md",
      "ro", "rm", "pa", "pt", "pt-br", "pl", "nn", "nb", "no", "mt", "ms", "ml", "mk", "lt", "lv", "ku", "ko", "ko", "ja", "it-ch", "it", "ga", "id", "is", "hu", "hi",
      "he", "el", "de-ch", "de", "de-lu", "de-li", "de-at", "gd", "fr-ch", "fr", "fr-lu", "fr-ca", "fr-be", "fi", "fa", "fo", "et", "en-us", "en-gb", "en-tt", "en-za",
      "en-nz", "en-jm", "en-ie", "en-ca", "en-bz", "en-au", "en", "nl", "nl-be", "da", "cs", "hr", "zh-tw", "zh-sg", "zh-hk", "zh-cn", "ca", "bg", "be", "eu", "ar-ye",
      "ar-ae", "ar-tn", "ar-sy", "ar-sa", "ar-qa", "ar-ma", "ar-om", "ar-ly", "ar-lb", "ar-kw", "ar-jo", "ar-iq", "ar-eg", "ar-bh", "ar-dz", "sq", "af"
    ]
    languages.sample
  end

  # Generate random browsers
  def self.rs_browser
    browsers = ["Safari", "Nexus", "Opera", "MSIE", "Intel Mac OS X", "UCWEB", "NOKIA", "Openwave", "Chromium", "Edge", "ARM Mac OS X", "Chrome", "Firefox", "ArkWeb"]
    browsers.sample
  end

  # Generate random encryption types
  def self.rs_encryption_u
    encryption_types = ["U", "I", "N"]
    encryption_types.sample
  end

  # Generate a random number of operating system bits
  def self.rs_platform_os_bit
    bits = ["WoW64", "WoW32"]
    bits.sample
  end

  # Generate a random browser kernel
  def self.rs_browser_kernel
    browser_kernels = ["AppleWebKit", "Gecko", "Opera", "Presto", "Chrome", "Maxthon"]
    browser_kernels.sample
  end

  # Generate a random version number
  def self.rs_version
    rand(1..2000).to_s
  end

  # Generate random browser names
  def self.rs_is_browser
    browsers = ["Chrome", "Firefox", "Edge", "Safari", "IE", "BrowserNG", "Opera", "Chromium", "OPR", "QQBrowser", "UBrowser", "TaoBrowser", "MetaSr", "ArkWeb"]
    browsers.sample
  end

end
