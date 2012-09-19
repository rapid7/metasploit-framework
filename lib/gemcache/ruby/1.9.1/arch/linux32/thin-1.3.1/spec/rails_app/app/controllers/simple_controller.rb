class SimpleController < ApplicationController
  caches_page :cached
  
  def index
  end
  
  def post_form
    render :text => params.to_yaml
  end
  
  def set_cookie
    cookies[params[:name]] = params[:value] if params[:name]
    render :text => cookies.to_yaml
  end
  
  def cached
    render :text => params[:value]
  end
end
