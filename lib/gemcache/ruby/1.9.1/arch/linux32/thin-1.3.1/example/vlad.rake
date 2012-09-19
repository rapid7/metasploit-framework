# $GEM_HOME/gems/vlad-1.2.0/lib/vlad/thin.rb
# Thin tasks for Vlad the Deployer
# By cnantais
require 'vlad'

namespace :vlad do
  ##
  # Thin app server

  set :thin_address,       "127.0.0.1"
  set :thin_command,       'thin'
  set(:thin_conf)          { "#{shared_path}/thin_cluster.conf" }
  set :thin_environment,   "production"
  set :thin_group,         nil
  set :thin_log_file,      nil
  set :thin_pid_file,      nil
  set :thin_port,          nil
  set :thin_socket,        nil
  set :thin_prefix,        nil
  set :thin_servers,       2
  set :thin_user,          nil

  desc "Prepares application servers for deployment. thin
configuration is set via the thin_* variables.".cleanup

  remote_task :setup_app, :roles => :app do
  
    raise(ArgumentError, "Please provide either thin_socket or thin_port") if thin_port.nil? && thin_socket.nil?
  
    cmd = [
           "#{thin_command} config",
           "-s #{thin_servers}",
           ("-S #{thin_socket}" if thin_socket),
           "-e #{thin_environment}",
           "-a #{thin_address}",
           "-c #{current_path}",
           "-C #{thin_conf}",
           ("-P #{thin_pid_file}" if thin_pid_file),
           ("-l #{thin_log_file}" if thin_log_file),
           ("--user #{thin_user}" if thin_user),
           ("--group #{thin_group}" if thin_group),
           ("--prefix #{thin_prefix}" if thin_prefix),
           ("-p #{thin_port}" if thin_port),
          ].compact.join ' '

    run cmd
  end

  def thin(cmd) # :nodoc:
    "#{thin_command} #{cmd} -C #{thin_conf}"
  end

  desc "Restart the app servers"

  remote_task :start_app, :roles => :app do
    run thin("restart -s #{thin_servers}")
  end

  desc "Stop the app servers"

  remote_task :stop_app, :roles => :app do
    run thin("stop -s #{thin_servers}")
  end
end
