require 'fileutils'
require 'timeout'
require 'stringio'
require 'time'
require 'forwardable'
require 'openssl'
require 'eventmachine'
require 'rack'

module Thin
  ROOT = File.expand_path(File.dirname(__FILE__))
  
  autoload :Command,            "#{ROOT}/thin/command"
  autoload :Connection,         "#{ROOT}/thin/connection"
  autoload :Daemonizable,       "#{ROOT}/thin/daemonizing"
  autoload :Logging,            "#{ROOT}/thin/logging"
  autoload :Headers,            "#{ROOT}/thin/headers"
  autoload :Request,            "#{ROOT}/thin/request"
  autoload :Response,           "#{ROOT}/thin/response"
  autoload :Runner,             "#{ROOT}/thin/runner"
  autoload :Server,             "#{ROOT}/thin/server"
  autoload :Stats,              "#{ROOT}/thin/stats"
  
  module Backends
    autoload :Base,             "#{ROOT}/thin/backends/base"
    autoload :SwiftiplyClient,  "#{ROOT}/thin/backends/swiftiply_client"
    autoload :TcpServer,        "#{ROOT}/thin/backends/tcp_server"
    autoload :UnixServer,       "#{ROOT}/thin/backends/unix_server"
  end
  
  module Controllers
    autoload :Cluster,          "#{ROOT}/thin/controllers/cluster"
    autoload :Controller,       "#{ROOT}/thin/controllers/controller"
    autoload :Service,          "#{ROOT}/thin/controllers/service"
  end
end

require "#{Thin::ROOT}/thin/version"
require "#{Thin::ROOT}/thin/statuses"
require "#{Thin::ROOT}/rack/adapter/loader"
require "#{Thin::ROOT}/thin_parser"

module Rack
  module Adapter
    autoload :Rails, "#{Thin::ROOT}/rack/adapter/rails"
  end
end
