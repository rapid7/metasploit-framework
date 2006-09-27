class SessionsController < ApplicationController
  layout 'windows'
  
  def list
    @all_sessions = Session.get_available()
  end

  def stop
  end

  def interact
  end
end
