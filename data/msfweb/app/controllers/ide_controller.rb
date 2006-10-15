# Author: L.M.H <lmh@info-pull.com>
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
      session[:exploit] = params[:exploit]
      @the_exploit = session[:exploit]
      @step = @the_exploit["step"].to_i
    elsif @step.nil?
      @step = 0
      @the_exploit = { }
    end
    
    flash[:error] = ""
    
    # lmh:
    # XXX: regex for validation needed, more nice method (helper anyone?) and polishing
    # the whole thing should be a helper that dumps errors to flash[:error] and returns
    # true or false depending on validation. false means @step = current (not next), true
    # means no changes in flow.
    case @step
      when 1
        if @the_exploit["name"].length < 5
          flash[:error] << "Name is too short or not specified. "
          @step = 0
        end
        if @the_exploit["description"].length < 5
          flash[:error] << "Description is too short or not specified. "
          @step = 0
        end
      when 2
        # XXX check valid os
        unless @the_exploit["os"].length > 0
          flash[:error] << "Platform not specified. "
          @step = 0
        end
        # XXX check valid archs ...
        unless @the_exploit["arch"].length > 0
          flash[:error] << "Architecture not specified. "
          @step = 0
        end
        # and so on....
      else
        # nothing
    end
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
