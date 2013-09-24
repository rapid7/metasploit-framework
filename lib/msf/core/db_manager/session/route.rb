module Msf::DBManager::Session::Route
  def report_session_route(session, route)
    return if not active
    if session.respond_to? :db_record
      s = session.db_record
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

    ::ActiveRecord::Base.connection_pool.with_connection {

      subnet, netmask = route.split("/")
      s.routes.create(:subnet => subnet, :netmask => netmask)
    }
  end

  def report_session_route_remove(session, route)
    return if not active
    if session.respond_to? :db_record
      s = session.db_record
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

    ::ActiveRecord::Base.connection_pool.with_connection {
      subnet, netmask = route.split("/")
      r = s.routes.find_by_subnet_and_netmask(subnet, netmask)
      r.destroy if r
    }
  end
end