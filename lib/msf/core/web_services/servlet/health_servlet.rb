module Msf::WebServices::HealthServlet

  def self.api_path
    '/api/v1/health'
  end

  def self.registered(app)
    app.get self.api_path, &health_check
  end

  #######
  private
  #######

  def self.health_check
    lambda {
      health_check = Msf::RPC::Health.check(framework)
      is_success = health_check[:status] == 'UP'
      set_json_data_response(response: health_check, code: is_success ? 200 : 503)
    }
  end
end
