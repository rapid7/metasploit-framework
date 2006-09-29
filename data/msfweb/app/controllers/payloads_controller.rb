# Author: L.M.H <lmh@info-pull.com>
# Description: The payload controller of msfweb v.3. Handles views, listing
# and other actions related to payload modules. Code and processing goes here.
# Instance variables, final values, etc, go into views.

class PayloadsController < ApplicationController
  layout 'windows'
      
  def list
  end

  def view
    @tmod = get_view_for_module("payload", params[:id])
	
	unless @tmod
	 render_text "Unknown module specified."
	end
	
	if params[:step]
	 @module_step = params[:step]
	end
	
  end

  def generate
  end
  
end
