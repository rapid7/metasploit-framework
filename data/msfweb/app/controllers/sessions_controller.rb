class SessionsController < ApplicationController

  def list
    @all_sessions = Session.get_available()
  end

  def stop
  end

  def interact
  end
end
