require 'msf/core/db_manager/session'

module Msf::DBManager::Route
  def report_session_route(opts)
    return if not active
    session = opts[:session]
    route = opts[:route]
    if session.respond_to? :db_record
      s = session.db_record
    elsif session.is_a?(Hash) && session.key?(:id)
      s = Mdm::Session.find(session[:id])
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

  ::ApplicationRecord.connection_pool.with_connection {

    subnet, netmask = route.split("/")
    s.routes.create(:subnet => subnet, :netmask => netmask)
  }
  end

  def report_session_route_remove(opts)
    return if not active
    session = opts[:session]
    route = opts[:route]
    if session.respond_to? :db_record
      s = session.db_record
    elsif session.is_a?(Hash) && session.key?(:id)
      s = Mdm::Session.find(session[:id])
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

  ::ApplicationRecord.connection_pool.with_connection {
    subnet, netmask = route.split("/")
    r = s.routes.find_by_subnet_and_netmask(subnet, netmask)
    r.destroy if r
  }
  end

end
