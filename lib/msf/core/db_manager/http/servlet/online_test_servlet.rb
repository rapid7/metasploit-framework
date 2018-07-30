module OnlineTestServlet

  def self.api_path
    '/api/v1/online'
  end

  def self.registered(app)
    app.get OnlineTestServlet.api_path, &get_active
  end

  #######
  private
  #######

  def self.get_active
    lambda {
      set_empty_response()
    }
  end

end