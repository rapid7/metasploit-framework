class JobsController < ApplicationController
  layout 'windows'
  
  def list
    @jobs = Job.find_all()
  end

  def stop
  end
end
