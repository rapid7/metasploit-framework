class DbInterface

  def init
    raise NotImplementedError
  end

  def delete
    raise NotImplementedError
  end

  def reinit
    raise NotImplementedError
  end

  def start
    raise NotImplementedError
  end

  def stop
    raise NotImplementedError
  end

  def restart
    raise NotImplementedError
  end

  def status
    raise NotImplementedError
  end

  def write_db_client_auth_config
    raise NotImplementedError
  end

  def self.requirements
    Array.new
  end

end
