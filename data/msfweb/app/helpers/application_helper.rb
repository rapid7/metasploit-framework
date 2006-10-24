# Copyright (c) 2006 L.M.H <lmh@info-pull.com>
# All Rights Reserved.

# Methods added to this helper will be available to all templates in the application.
module ApplicationHelper

  # Returns a hash with ruby version, platform and Metasploit version.
  def return_env_info()
    ret = {}
    ret[:platform] = RUBY_PLATFORM
    ret[:rubyver]  = RUBY_VERSION
    ret[:msfver]   = Msf::Framework::Version
    return ret
  end
  
  # Return the JavaScript code necessary for "supporting" :hover pseudo-class
  # in MSIE (ex. used in the top menu bar).
  def msie_hover_fix(css_class_name)
    return "onmouseover=\"this.className='#{css_class_name}'\" onmouseout=\"this.className=''\""
  end
  
  # Adapted from old msfweb code, returns HTML necessary for displaying icons
  # associated with a specific module.
  # Added missing platform icons (HPUX, Irix, etc).
  def module_platform_icons(platform)
    return "" if (platform.nil?)
    
    # If this module has no platforms, then we don't show any icons...
    return "" if (platform.empty?)

    # Otherwise, get the platform specific information...
    html = ""
    [
      [ Msf::Module::Platform::Windows, "windows.png", "win32"   ],
      [ Msf::Module::Platform::Linux,   "linux.png",   "linux"   ],
      [ Msf::Module::Platform::Solaris, "sun.png",     "solaris" ],
      [ Msf::Module::Platform::OSX,     "apple.png",   "osx"     ],
      [ Msf::Module::Platform::BSD,     "bsd.gif",     "bsd"     ],
      [ Msf::Module::Platform::BSDi,    "bsd.gif",     "bsdi"    ],
      [ Msf::Module::Platform::HPUX,    "hp.png",      "hpux"    ],
      [ Msf::Module::Platform::Irix,    "sgi.png",     "irix"    ],
      [ Msf::Module::Platform::Unix,    "unix.png",    "unix"    ]
    ].each do |plat|
      if (platform.supports?(Msf::Module::PlatformList.new(plat[0])) == true)
        html += "<img src=\"/images/platform-icons/#{plat[1]}\" alt=\"#{plat[2]}\"/>"
      end
    end
    
    return html
  end
  
  # Returns a hash suitable for use with select method (FormHelper stuff) of
  # the available platforms.
  def return_selectable_platforms()
    all_platforms = Msf::Module::Platform::find_children
    select_list   = {}
    all_platforms.each do |p|
      select_list[p.realname] = p
    end
    return select_list
  end
  
  # Returns an array suitable for use with select method (FormHelper stuff) of
  # the supported architectures.
  def return_selectable_architectures()
    return ARCH_ALL
  end

  # Returns an array suitable for the select form option helper,
  # of the available exploit mixins. thanks skape for the new method.
  def return_selectable_exploit_mixins()
    Msf::Exploit::mixins
  end

  # Returns an array suitable for the select form option helper,
  # of the available module licenses.
  def return_selectable_licenses()
    LICENSES
  end
end
