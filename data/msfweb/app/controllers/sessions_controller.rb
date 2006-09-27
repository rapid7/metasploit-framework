class SessionsController < ApplicationController
  layout 'windows'
  
  def list
    @sessions = Session.find_all()
  end

  def stop
  end

  def interact
  end
end
