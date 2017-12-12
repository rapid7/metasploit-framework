require 'metasploit/framework/data_service'
require 'metasploit/framework/data_service/remote/http/core'
require 'metasploit/framework/data_service/remote/http/remote_service_endpoint'

class MSFRedService
  JOB_CHECK_INTERVAL_SEC = 5
  LOGIN_TIMEOUT_SEC = 10
  SESSION_KEY_VALUE = 'msf-session-key'
  LOGIN_ENDPOINT = '/login'
  JOBS_ENDPOINT = '/jobs'
  CONSOLE_SERVICE_HOST_NAME = 'console-service.metasploit.r7ops.com'
  CONSOLE_SERVICE_PORT = 8080

  def initialize
    @client = Rex::Proto::Http::Client.new(CONSOLE_SERVICE_HOST_NAME, CONSOLE_SERVICE_PORT)
    @job_handlers = Hash.new()
    load_job_handlers
  end

  # TODO: Obviously this is not secure
  def launch(username, password)
    if (do_login(username, password))
      inject_data_service
      start_job_thread
    end

  end

  #######
  private
  #######

  def load_job_handlers
      job_handler_path = File.dirname(__FILE__) + '/job_handlers/*'
      Dir.glob(job_handler_path).collect{|file_path|
        job_handler_class = File.basename(file_path, '.rb').classify
        require file_path
        job_handler_class_constant = job_handler_class.constantize
        job_handler = job_handler_class_constant.new
        @job_handlers[job_handler.job_type_handled] = job_handler
      }
  end

  def inject_data_service
    endpoint = URI.parse("http://#{CONSOLE_SERVICE_HOST_NAME}:#{CONSOLE_SERVICE_PORT}")
    remote_data_service = Metasploit::Framework::DataService::RemoteHTTPDataService.new(endpoint)
    remote_data_service.set_header(SESSION_KEY_VALUE, @session_key)
    data_service_manager = Metasploit::Framework::DataService::DataProxy.instance
    data_service_manager.register_data_service(remote_data_service)
  end

  def do_login(username, password)
    login_hash = {:username => username, :password => password}
    begin

      request_opts = { 'method' => 'POST', 'ctype' => 'application/json', 'uri' => LOGIN_ENDPOINT, 'data' => login_hash.to_json }
      request = @client.request_raw(request_opts)
      response = @client._send_recv(request, LOGIN_TIMEOUT_SEC)

      if response.code == 200
        data = JSON.parse(response.body)
        @session_key =  data['session_key']
        puts "MSF Red console login successfull, session: #{@session_key}"
        return true
      else
        puts "Login failed: failed with code: #{response.code} message: #{response.body}"
        return false
      end
    rescue Exception => e
      puts "Problem with POST request: #{e.message}"
      return false
    end
  end


  def start_job_thread
    Thread.start {
      loop  {
        sleep 5
        begin
          job_hash = get_next_job
          if (job_hash.nil? or job_hash.empty?)
            next
          end

          type = job_hash['job_type']
          job_handler = @job_handlers[type]
          if (job_handler.nil?)
            puts "No registered job handler for type: #{type}"
          else
            job_handler.handle(job_hash['job_details'])
          end
        rescue Exception => e
          puts "Problem executing job: #{e.message}"
        end
      }
    }
  end

  def get_next_job
    request_opts = { 'method' => 'GET', 'ctype' => 'application/json', 'uri' => JOBS_ENDPOINT, 'headers' => {SESSION_KEY_VALUE => @session_key} }
    request = @client.request_raw(request_opts)
    response = @client._send_recv(request)

    if response.code == 200
      if (response.body.nil? or response.body.empty?)
        return nil
      end

      begin
        return JSON.parse(response.body)
      rescue Exception => e
        puts "Unable to parse: #{response.body}, reason: #{e.message}"
        return nil
      end

    else
      puts "GET request: #{path} with body: #{json_body} failed with code: #{response.code} message: #{response.body}"
      return nil
    end
  end

end