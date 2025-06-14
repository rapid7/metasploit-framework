# -*- coding: binary -*-
require 'msgpack'

require 'rex'

module Msf
module RPC

class Service

  attr_accessor :service, :srvhost, :srvport, :uri, :options
  attr_accessor :handlers, :default_handler, :tokens, :users, :framework
  attr_accessor :dispatcher_timeout, :token_timeout, :debug, :str_encoding
  attr_accessor :job_status_tracker

  def initialize(framework, options={})
    self.framework = framework
    self.handlers = {}
    self.options  = {
      :ssl  => true,
      :cert => nil,
      :uri  => "/uri",
      :host => '127.0.0.1',
      :port => 3790
    }.merge(options)

    self.str_encoding = ''.encoding.name
    self.srvhost = self.options[:host]
    self.srvport = self.options[:port]
    self.uri     = self.options[:uri]
    self.debug   = self.options[:debug]

    self.dispatcher_timeout = self.options[:dispatcher_timeout] || 7200
    self.token_timeout      = self.options[:token_timeout] || 300
    self.tokens             = self.options[:tokens] || {}
    self.users              = self.options[:users] || []
    self.job_status_tracker = Msf::RPC::RpcJobStatusTracker.new

    add_handler("health",  Msf::RPC::RPC_Health.new(self))
    add_handler("core",    Msf::RPC::RPC_Core.new(self))
    add_handler("auth",    Msf::RPC::RPC_Auth.new(self))
    add_handler("console", Msf::RPC::RPC_Console.new(self))
    add_handler("module",  Msf::RPC::RPC_Module.new(self))
    add_handler("session", Msf::RPC::RPC_Session.new(self))
    add_handler("plugin",  Msf::RPC::RPC_Plugin.new(self))
    add_handler("job",     Msf::RPC::RPC_Job.new(self))
    add_handler("db",      Msf::RPC::RPC_Db.new(self))
  end

  def start
    self.service = Rex::ServiceManager.start(
      Rex::Proto::Http::Server,
      self.srvport,
      self.srvhost,
      self.options[:ssl],
      self.options[:context],
      self.options[:comm],
      self.options[:cert]
    )

    self.service.add_resource(self.uri, {
      'Proc' => Proc.new { |cli, req| on_request_uri(cli, req) },
      'Path' => self.uri
    })
  end

  def stop
    self.service.stop
    self.service.deref
  end

  def wait
    self.service.wait
  end

  def on_request_uri(cli, req)
    res = Rex::Proto::Http::Response.new()
    res["Content-Type"] = "binary/message-pack"

    begin
      res.body = process(req).to_msgpack
    rescue Msf::RPC::Exception => e
      elog('RPC Exception', error: e)
      res.body = process_exception(e).to_msgpack
      res.code = e.code
    end
    cli.send_response(res)
  end

  def add_handler(group, handler)
    self.handlers[group] = handler
  end

  def process(req)
    msg  = nil

    begin
      if req.method != "POST"
        if req && req.method
          raise ArgumentError, "Invalid Request Verb: '#{req.method.inspect}'"
        else
          raise ArgumentError, "Invalid Request: '#{req.inspect}'"
        end
      end

      unless (req.headers["Content-Type"] && req.headers["Content-Type"] == "binary/message-pack")
        raise ArgumentError, "Invalid Content Type"
      end

      msg = MessagePack.unpack(req.body)

      unless (msg && msg.kind_of?(::Array) && msg.length > 0)
        raise ArgumentError, "Invalid Message Format"
      end

      msg.map { |a| a.respond_to?(:force_encoding) ? a.force_encoding(self.str_encoding) : a }

      group, funct = msg.shift.split(".", 2)

      unless self.handlers[group]
        raise ArgumentError, "Unknown API Group: '#{group.inspect}'"
      end

      doauth = true
      mname  = 'rpc_' + funct

      if self.handlers[group].respond_to?(mname + '_noauth')
        doauth = false
        mname << '_noauth'
      end

      unless self.handlers[group].respond_to?(mname)
        raise ArgumentError, "Unknown API Call: '#{mname.inspect}'"
      end

      if doauth
        token = msg.shift
        unless authenticate(token)
          raise ::Msf::RPC::Exception.new(401, "Invalid Authentication Token")
        end
      end

      ::Timeout.timeout(self.dispatcher_timeout) do
        Thread.current[:rpc_token] = token
        self.handlers[group].send(mname, *msg)
      end

    rescue ::Exception => e
      elog('RPC Exception', error: e)
      process_exception(e)
    ensure
      Thread.current[:rpc_token] = nil
    end
  end

  def process_exception(e)
    r = {
      :error           => true,
      :error_class     => e.class.to_s,
      :error_string    => e.to_s,
      :error_backtrace => e.backtrace.map{|x| x.sub(/^.*lib\//, 'lib/') } # Dont expose the install path
    }

    if e.respond_to?(:message)
      r[:error_message] = e.message
    end

    if e.respond_to?(:code)
      r[:error_code] = e.code
    end

    r
  end


  def add_token(token)
    self.tokens[token] = [nil, nil, nil, true]
  end

  def remove_token
    self.tokens.delete(token)
  end

  def add_user(user, pass)
    self.users.each do |r|
      if r[0] == user
        r[1] = pass
        return
      end
    end
    self.users << [user, pass]
  end

  def remove_user(user)
    self.users = self.users.select{|r| r[0] != user }
  end

  def authenticate(token)
    stale = []


    unless (token && token.kind_of?(::String))
      return false
    end

    # Force the encoding to ASCII-8BIT
    token = token.unpack("C*").pack("C*")

    self.tokens.each_key do |t|
      user,ctime,mtime,perm = self.tokens[t]
      if !perm && mtime + self.token_timeout < Time.now.to_i
        stale << t
      end
    end

    stale.each { |t| self.tokens.delete(t) }

    unless self.tokens[token]

      begin
        if framework.db.active && ::Mdm::ApiKey.find_by_token(token)
          return true
        end
      rescue ::Exception => e
      end

      return false
    end

    self.tokens[token][2] = Time.now.to_i
    true
  end
end

end
end

