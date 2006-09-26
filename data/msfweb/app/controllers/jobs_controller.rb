class JobsController < ApplicationController

  def list
    @all_jobs = Job.get_available()
  end

  def stop
  end
end
