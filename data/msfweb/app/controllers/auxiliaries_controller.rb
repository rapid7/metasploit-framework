#
# Original version is Copyright (c) 2006 LMH <lmh[at]info-pull.com>
# Added to Metasploit under the terms of the Metasploit Framework License v1.2
#
# Description: The auxiliary controller of msfweb v.3. Handles views, listing
# and other actions related to auxiliary modules. Code and processing goes here.
# Instance variables, final values, etc, go into views.

class AuxiliariesController < ApplicationController
  layout 'windows'
    
  def list
  end

  def view
    @tmod = get_view_for_module("auxiliary", params[:refname])
	
	unless @tmod
	 render_text "Unknown module specified."
	end
  end

  def run
  end
end
