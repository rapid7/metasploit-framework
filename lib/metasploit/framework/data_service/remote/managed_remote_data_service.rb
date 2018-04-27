require 'singleton'
require 'metasploit/framework/data_service/remote/http/core'

module Metasploit
module Framework
module DataService

#
#  Primarily for testing this instance is used to manage a data service started within a separate process.
#
class ManagedRemoteDataService
  include Singleton

  #
  # Returns true if the the managed data service process is running.
  #
  def running?
    return @running
  end

  #
  # Returns the client used to interact with the remote data service
  #
  def remote_data_service
    return @remote_host_data_service
  end

  #
  # Starts a remote data service process
  #
  def start(opts)
    @mutex.synchronize do

      return if @running

      # started with no signal to prevent ctrl-c from taking out db
      db_script = File.join( Msf::Config.install_root, opts[:process_name])
      wait_t = Open3.pipeline_start(db_script)
      @pid = wait_t[0].pid
      puts "Started process with pid #{@pid}"

      endpoint = "http://#{opts[:host]}:#{opts[:port]}"
      @remote_host_data_service = Metasploit::Framework::DataService::RemoteHTTPDataService.new(endpoint)

      count = 0
      loop do
        count = count + 1
        if count > 10
          raise 'Unable to start remote data service'
        end

        sleep(1)

        if @remote_host_data_service.is_online?
          break
        end
      end

      @running = true
    end

  end

  #
  # Stops the remote data service process
  #
  # NOTE: This has potential issues on windows
  #
  def stop
    @mutex.synchronize do
      return unless @running

      begin
        Process.kill("TERM", @pid)
        @running = false
      rescue Exception => e
        puts "Unable to kill db process: #{e.message}"
      end
    end
  end

  #######
  private
  #######

  def initialize
    @mutex = Mutex.new
    @running = false
  end
end

end
end
end
