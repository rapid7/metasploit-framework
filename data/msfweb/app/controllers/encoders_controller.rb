# Author: LMH <lmh@info-pull.com>
# Description: The encoder controller of msfweb v.3. Handles views, listing
# and other actions related to encoder modules. Code and processing goes here.
# Instance variables, final values, etc, go into views.

class EncodersController < ApplicationController
  layout 'windows'
    
  def list
  end

  def view
    @tmod = get_view_for_module("encoder", params[:refname])
	
	unless @tmod
	 render_text "Unknown module specified."
	end
  end

  def encode
  end
end
