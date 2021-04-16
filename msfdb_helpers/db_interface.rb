class DbInterface

  def init_db
    raise NotImplementedError
  end

  def delete_db
    raise NotImplementedError
  end

  def reinit_db
    raise NotImplementedError
  end

  def start_db
    raise NotImplementedError
  end

  def stop_db
    raise NotImplementedError
  end

  def restart_db
    raise NotImplementedError
  end

  def status_db
    raise NotImplementedError
  end

  def write_db_client_auth_config
    raise NotImplementedError
  end

end
