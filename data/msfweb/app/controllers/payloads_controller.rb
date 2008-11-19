# Author: LMH <lmh@info-pull.com>
# Description: The payload controller of msfweb v.3. Handles views, listing
# and other actions related to payload modules. Code and processing goes here.
# Instance variables, final values, etc, go into views.

class PayloadsController < ApplicationController
  layout 'windows'
      
  def list
  end

  def view
    @tmod = get_view_for_module("payload", params[:refname])
	
	unless @tmod
		render_text "Unknown module specified."
	end

	# Catch non-standard payloads
	begin
		@tmod.generate
	rescue => e
		render_text "This interface does not support generic payloads."
	end

    @module_step = (params[:step] || 0).to_i
	
	if @module_step == 1
	  modinst = Payload.create(@tmod.refname)
      badchars = params[:badchars]
      pencoder = params[:encoder]
      pformat  = params[:format]
      max_size = (params[:max_size] || 0).to_i
      payload_opts = ''
      
      params.each_pair { |k, v|
        next if (v == nil or v.length == 0)
        if (k =~ /^opt_(.*)$/)
          payload_opts += "#{$1}=#{v} "
        end
      }
	  
	  
	  badchars_buff = ""
	  badchars.split(/,|\s+/).each do |c|
		c.strip!
		next if c.length == 0
		if(c =~ /^0x/)
			badchars_buff << c.hex.chr
		else
			badchars_buff << c.to_i.chr
		end
	  end
	  
      begin
        @generation = modinst.generate_simple(
          'Encoder'   => (pencoder == '__default') ? nil : pencoder,
          'BadChars'  => badchars_buff,
          'Format'    => pformat || 'c',
          'OptionStr' => payload_opts,
          'MaxSize'   => (max_size == 0) ? nil : max_size)
      rescue
        @generation = $!
      end
	end
  # end of view method
  end

  def generate
  end
  
end
