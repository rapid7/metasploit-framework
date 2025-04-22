module Rex::UserAgent_Random
  attr_reader :user_agent

  # 随机user-agent
  def initialize
    # 设置 user-agent 用来躲避追踪
    is_kernel_version = "#{rs_version}.#{rs_version}.#{rs_version}"
    is_browser_version = "#{rs_version}.#{rs_version}.#{rs_version}"
    @user_agent = "#{rs_mozilla_version}#{rs_platform} #{rs_browser_kernel}/#{is_kernel_version} #{rs_is_browser}/#{is_browser_version}"
  end

  private

  # 生成随机 Mozilla 版本
  def rs_mozilla_version
    random_number = rand(4..200)
    "Mozilla/#{random_number}.0 "
  end

  # 生成随机平台信息
  def rs_platform
    operating_systems = ["Windows", "Mac", "Linux", "Android", "Windows NT 6.1, OpenHarmony", "Phone", "HarmonyOS"]
    random_os = operating_systems.sample
    "(#{random_os}; #{rs_platform_os_bit}; #{rs_browser}; #{rs_encryption_u}; #{rs_language})"
  end

  # 生成随机语言
  def rs_language
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

  # 生成随机浏览器
  def rs_browser
    browsers = ["Safari", "Nexus", "Opera", "MSIE", "Intel Mac OS X", "UCWEB", "NOKIA", "Openwave", "Chromium", "Edge", "ARM Mac OS X", "Chrome", "Firefox", "ArkWeb"]
    browsers.sample
  end

  # 生成随机加密类型
  def rs_encryption_u
    encryption_types = ["U", "I", "N"]
    encryption_types.sample
  end

  # 生成随机操作系统位数
  def rs_platform_os_bit
    bits = ["WoW64", "WoW32"]
    bits.sample
  end

  # 生成随机浏览器内核
  def rs_browser_kernel
    browser_kernels = ["AppleWebKit", "Gecko", "Opera", "Presto", "Chrome", "Maxthon"]
    browser_kernels.sample
  end

  # 生成随机版本号
  def rs_version
    rand(1..2000).to_s
  end

  # 生成随机浏览器名称
  def rs_is_browser
    browsers = ["Chrome", "Firefox", "Edge", "Safari", "IE", "BrowserNG", "Opera", "Chromium", "OPR", "QQBrowser", "UBrowser", "TaoBrowser", "MetaSr", "ArkWeb"]
    browsers.sample
  end
end