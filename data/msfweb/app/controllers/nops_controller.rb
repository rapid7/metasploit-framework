# Author: LMH <lmh@info-pull.com>
# Description: The nop controller of msfweb v.3. Handles views, listing
# and other actions related to nop modules. Code and processing goes here.
# Instance variables, final values, etc, go into views.

class NopsController < ApplicationController
  layout 'windows'

  def list
  end

  def view
    @tmod = get_view_for_module("nop", params[:refname])
	
	unless @tmod
	 render_text "Unknown module specified."
	end
  end

  def generate
  end
end
