#
# Original version is Copyright (c) 2006 LMH <lmh[at]info-pull.com>
# Added to Metasploit under the terms of the Metasploit Framework License v1.2
# Additions Copyright (C) 2006-2007 Metasploit LLC
#
# Description: The main controller of msfweb v.3
#

class MsfController < ApplicationController
  layout 'msfweb', :except => 'search'
  
  def index
  end
  
  # Generic search function as suggested by HDM
  def search
    if params[:module_type]
      @module_type = params[:module_type]
      if params[:clean_list] and params[:clean_list].to_i == 1
        @clean_list = true
      else
        @clean_list = false
      end
      if params[:terms]
        case @module_type
          when 'exploits'
	       @results = search_modules(Exploit.find_all(), params[:terms])
	      when 'auxiliaries'
	       @results = search_modules(Auxiliary.find_all(), params[:terms])
	      when 'payloads'
	       @results = search_modules(Payload.find_all(), params[:terms])
	      when 'nops'
	       @results = search_modules(Nop.find_all(), params[:terms])
	      when 'encoders'
	       @results = search_modules(Encoder.find_all(), params[:terms])
	      else
	       render_text "Module type unknown."
	    end
	  else
	   render_text "No search terms provided."
	  end
	else
	 render_text "Module type not specified."
	end
  end

end
