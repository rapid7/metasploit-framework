# Events that can occur in the host/service database.
module Msf::DatabaseEvent

  #
  # Called when an existing host's state changes
  #
  def on_db_host_state(host, ostate)
  end

  #
  # Called when an existing service's state changes
  #
  def on_db_service_state(host, port, ostate)
  end

  #
  # Called when a new host is added to the database.  The host parameter is
  # of type Host.
  #
  def on_db_host(host)
  end

  #
  # Called when a new client is added to the database.  The client
  # parameter is of type Client.
  #
  def on_db_client(client)
  end

  #
  # Called when a new service is added to the database.  The service
  # parameter is of type Service.
  #
  def on_db_service(service)
  end

  #
  # Called when an applicable vulnerability is found for a service.  The vuln
  # parameter is of type Vuln.
  #
  def on_db_vuln(vuln)
  end

  #
  # Called when a new reference is created.
  #
  def on_db_ref(ref)
  end

end
