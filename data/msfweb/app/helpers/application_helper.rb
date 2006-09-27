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
    return "onMouseOver=\"this.className='#{css_class_name}'\" onMouseOut=\"this.className=''\""
  end
  
  # Return the AJAX livesearch-ready text box and target div container for eacrh results.
  def ajax_livesearch_for(mod)
    my_keyup_event = "window.parent.return_livesearch_results(this.value, '#{mod}', 'search-results')"
    text_field     = "<input type=\"text\" onKeyup=\"#{my_keyup_event}\"/>"
    search_target  = '<div id="search-results"></div>'
    search_box = '<div id="search-box">' + text_field + search_target + '</div>'
    return search_box
  end
  
end
