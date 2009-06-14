# Author: LMH <lmh@info-pull.com>
# Description: The IDE controller of msfweb v.3. Handles views, processing,
# help and all actions related to the msfweb IDE for exploit development.
# Now Metasploit has a multi-platform IDE. Find bug. Click. Profit. (tm)

class IdeController < ApplicationController
  layout 'msfide'

  def index
    redirect_to :action => "start"
  end

  def start
  end

  def advanced
  end
  
  def wizard
    if params[:exploit]
      @the_exploit = session[:exploit] = params[:exploit]
      @step = @the_exploit["step"].to_i
    elsif @step.nil?
      redirect_to :action => start
    end
    
    flash[:error] = ""
  end

  def dump_current()
    unless params[:format]
      render_text "Missing format parameter."
      return false
    end

    unless session[:exploit]
      render_text "Missing exploit data."
      return false
    end

    case params[:format]
      when "yaml"
        send_data YAML.dump(session[:exploit]), :type => "text/plain"
      else
        render_text "Missing format parameter."
        return false
    end
  end
end
