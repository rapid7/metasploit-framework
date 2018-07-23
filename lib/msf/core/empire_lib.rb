require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'rex/ui/subscriber.rb'
#Methods used to call the Empire-WebAPI
module Msf::Empire
  class Client
    include Rex::Ui::Subscriber
    #
    #API INITIATION METHODS
    #-----------------------
    @token = ''
    def set_options(uri)
      req_options = {
        use_ssl: uri.scheme == "https",
        verify_mode: OpenSSL::SSL::VERIFY_NONE
      }
      return req_options
    end
    #
    #Method to fetch the active session token from the hosted API
    #
    def initialize(username, password)
      uri = URI.parse("https://localhost:1337/api/admin/login")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "username" => username,
        "password" => password
        })
      req_options={
        use_ssl: uri.scheme == "https",
        verify_mode: OpenSSL::SSL::VERIFY_NONE
      }
      response = Net::HTTP.start(uri.hostname, uri.port,req_options) do |http|
        http.request(request)
      end
      parser = JSON.parse(response.body)
      token = parser['token'].to_s
      @token = token
      puts(@token)
    end
    #
    #Method to shutdown the active instance of API
    #
    def shutdown
      uri = URI.parse("https://localhost:1337/api/admin/shutdown?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
    end
    #LISTENER METHODS
    #-----------------
    #
    #Method to create a listener, requires a port number and the listener
    #name. A port number different from 1337 must be used as the Web API itself is
    #hosted over there. Also, the name needs to be cross-checked with the existing listener names, so user doesnt end
    #creating concurrent listeners.
    #
    def create_listener(listener_name, port, host)
      target_host = "http://#{host}:#{port}"
      uri = URI.parse("https://localhost:1337/api/listeners/http?token=#{@token}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      req_options = self.set_options(uri)
      request.body = JSON.dump({
        "Name" => listener_name,
        "Port" => port,
        "Host" => target_host
        })
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.body.to_s.include?("error")
        return "Failed to bind to localhost:#{port}, port likely already in use"
      elsif response.body.to_s.include?("success")
        return "Listener #{listener_name} started at localhost:#{port}"
      end
    end
    #
    #Method to check if a lsietener with the listenername already exists.
    #
    def is_listener_active(listener_name)
      uri = URI.parse("https://localhost:1337/api/listeners/#{listener_name}?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.body.to_s.include?("error")
        return false
      else
        parser = JSON.parse(response.body)
        active_port = parser['listeners'][0]['options']['Port']['Value']
        return "The listener: #{listener_name} is active on #{active_port}"
      end
    end
    #
    #Method to terminate a particular listener - active or inactive
    #
    def kill_listener(listener_name)
      uri = URI.parse("https://localhost:1337/api/listeners/#{listener_name}?token=#{@token}")
      request = Net::HTTP::Delete.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.code == "200"
        return "Listener: #{listener_name} succesfully terminated"
      elsif response.code == "404"
        return "Listener : #{listener_name} not found"
      end
    end
    #
    #Method to terminate all active or inactive listeners
    #
    def kill_all_listeners
      uri = URI.parse("https://localhost:1337/api/listeners/all?token=#{@token}")
      request = Net::HTTP::Delete.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port,req_options) do |http|
        http.request(request)
      end
      if response.code == '200'
        return "All listeners terminated"
      end
    end
    #
    #STAGER METHODS
    #---------------
    #
    #Method to create a standalone Empire stager. As few problems are faced by parsing the "OutFile" parameter
    #in the request, Outfile needs to be set to '', which will ask the API to give the 'Output' through the response
    #which then needs to be written to file with proper extensions, for an instance, /tmp/launcher.dll
    #
    def gen_stager(listener_name, stager_type, payload_path)
      uri = URI.parse("https://localhost:1337/api/stagers?token=#{@token}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "StagerName" => stager_type,
        "Listener" => listener_name,
        "OutFile" => ""
      })
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.code == "404"
        return "Invalid stager type"
      elsif response.code == "200"
        parser = JSON.parse(response.body)
        payload = File.open(payload_path, "w")
        payload.puts parser[stager_type]['Output']
        payload.close
        return "Payload created succesfully at #{payload_path}"
      end
    end
    #
    #AGENT METHODS
    #--------------
    #
    #Method to list all the active agents connected. The temp_session
    #parameter determines if the session is being used by a post exploit
    #upgrade or a standalone stager, which will make it easier to guess the
    #number of agents connected
    #
    def get_agents
      agents = {}
      uri = URI.parse("https://localhost:1337/api/agents?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.message.to_s == 'OK'
        parser = JSON.parse(response.body)
        if parser['agents'].any?
          parser['agents'].each do |agent_id|
            agents.store("#{agent_id['listener']}","#{agent_id['session_id']}")
          end
          return agents
        else
          return "No agents connected"
        end
      else
        return "Invalid Request"
      end
     end
    #
    #Method to get all stale or idle agents
    #
    def get_stale
      uri = URI.parse("https://localhost:1337/api/agents/stale?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.message.to_s == 'OK'
        parser = JSON.parse(response.body)
        if parser['agents'].any?
          parser['agents'].each do |agents_id|
            print_line("#{agents_id['ID']} : #{agents_id['session_id']}")
          end
        else
          return "No stale agents"
        end
      else
        return "Invalid Request"
      end
    end
    #
    #Method to Rename an agent.
    #The current name of the agent is necessary to rename it.
    #
    def rename_agent(agent_name, new_name)
      uri = URI.parse("https://localhost:1337/api/agents/#{agent_name}/rename?token=#{@token}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      req_options = self.set_options(uri)
      request.body = JSON.dump({
        "newname" => new_name
      })
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.message.to_s == 'OK'
        return "Agent Renamed : #{new_name}"
      else
        return "Invalid Request"
      end
    end
    #
    #Method to kill a partcular agent
    #
    def kill_agent(agent_name)
      uri = URI.parse("https://localhost:1337/api/agents/#{agent_name}/kill?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      request.content_type = "application/json" 
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.message.to_s == 'OK'
        return "Agent Terminated : #{agent_name}"
      else
        return "Invalid Request"
      end
    end
    #
    #Method to kill all active and stale agents
    #
    def kill_all_agents
      uri = URI.parse("https://localhost:1337/api/agents/all/kill?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      request.content_type = "application/json" 
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.message.to_s == 'OK'
        return "All Agent Terminated"
      else
        return "Invalid Request"
      end
    end
    #
    #COMMAND EXECUTION METHODS
    #--------------------------
    #
    #In Empire code execution is not a single process. 
    #The first step is to task an agent to execute a command. The command gets executed and
    #and stored in the results. Then a result method is used to retrieve the outputs of the 
    #commands executed
    #
    #Method to task an agent to execute a command
    #
    def exec_command(agent_name, command)
      uri = URI.parse("https://localhost:1337/api/agents/#{agent_name}/shell?token=#{@token}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
        "command" => command
      })
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      parser = JSON.parse(response.body)
      if parser['success']
        puts "Command executed with TaskID : #{parser['taskID']}."
        return parser['taskID']
      else
        return "Error executing command"
      end
    end
    #
    #Method to retrieve results from the tasks assigned to a particular agent
    #
    def get_results(agent_name, taskID)
      uri = URI.parse("https://localhost:1337/api/agents/#{agent_name}/results?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      request.content_type = "application/json"
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port,req_options) do |http|
        http.request(request)
      end
      if response.code == 200
        parser = JSON.parse(response.body)
        if parser['results'][0]['AgentResults'].any?
          parser['results'][0]['AgentResults'].each do |results|
            if results['taskID'] == taskID
              if results['results'] != ""
                return results['results']
              else
                return "Command Launched"
              end
            end
          end
        else
          "No results found"
        end
      else
        return "Invalid request"
      end
    end
    #
    #Method to delete the results for a particular agent
    #
    def delete_results(agent_name)
      uri = URI.parse("https://localhost:1337/api/agents/#{agent_name}/results?token=#{@token}")
      request = Net::HTTP::Delete.new(uri)
      request.content_type = "application/json"
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port,req_options) do |http|
        http.request(request)
      end
    end
    #
    #Method to clear the queued up task of an agent
    #
    def clear_queue(agent_name)
      uri = URI.parse("https://localhost:1337/api/agents/#{agent_name}/clear?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      request.content_type = "application/json"
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
    end
    #
    #Method task every agent with a shell command
    #
    def task_all_agent(command)
      uri = URI.parse("https://localhost:1337/api/agents/all/shell?token=#{@token}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
          "command" => command
      })
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.to_s.include?("success")
        return "All agents tasked"
      else
        return "Error tasking agents"
      end
    end
    #
    #Method to delete every result for every active agent from the database
    #
    def delete_all_results
      uri = URI.parse("https://localhost:1337/api/agents/all/results?token=#{@token}")
      request = Net::HTTP::Delete.new(uri)
      request.content_type = "application/json"
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
    end
    #
    #MODULE METHODS
    #----------------
    #
    #This method will list all the avialbale post-exploitation modules for the agent. The response contains the details
    #of every module. Instead, this method will return an hash of just the names of the modules.
    #User can thereafter query about a specific module and get those details.
    #
    def get_modules
      uri = URI.parse("https://localhost:1337/api/modules?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.code == 200
        parser = JSON.parse(response.body)
        parser['modules'].each do |empire_module|
          print_line("#{empire_module['Name']} : #{empire_module['Description']}")
        end
      end
    end
     #
    #Method to get detailed information about a particular module
    #
    def info_module(module_name)
      uri = URI.parse("https://localhost:1337/api/modules/#{module_name}?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      if response.code == 200
        parser = JSON.parse(response.body)
        parser['modules'][0].each do |attribute, description|
          if attribute != 'options'
            puts "#{attribute} : #{description}"
          else
            puts "--------------------\n"
            puts "AVAILABLE OPTIONS\n"
            puts "--------------------"
            description.each do |option, options|
              puts "#{option} :\n"
              options.each do |attr, value|
                puts "\t #{attr} : #{value}"
              end
            end
          end
        end
      else
        puts "Invalid module name"
      end
     end
    #
    #Method to execute a module to a particular agent
    #
    def exec_module(module_name, agent_name)
      uri = URI.parse("https://localhost:1337/api/modules/#{module_name}?token=#{@token}")
      request = Net::HTTP::Post.new(uri)
      request.content_type = "application/json"
      request.body = JSON.dump({
          "Agent" => agent_name
      })
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
        http.request(request)
      end
      parser = JSON.parse(response.body)
      if parser['success']
        return "#{parser['msg']} with TaskID : #{parser['taskID']}\n. It take time to populate the results. Please wait few seconds before you fetch results."
      else
        return "Invalid request"
      end
    end
    #
    #CREDENTIAL HARVESTING METHODS
    #
    #This method will help harvesting all the credentials saved in the database for every host and will display it to the user.
    #
    def get_creds
      uri = URI.parse("https://localhost:1337/api/creds?token=#{@token}")
      request = Net::HTTP::Get.new(uri)
      req_options = self.set_options(uri)
      response = Net::HTTP.start(uri.hostname, uri.port,req_options) do |http|
        http.request(request)
      end
      i = 1
      if response.code == 200
        parser = JSON.parse(response.body)
        parser['creds'].each do |cred|
          puts "-----------------------------\n"
          puts "CREDENTIAL DETAILS {#{i}}\n"
          puts "-----------------------------"
          cred.each do |attr, detail|
            puts "#{attr} :: #{detail}\n"
          end
          i = i + 1
        end
      else
        print_error("Invalid request")
      end
    end
  end
end
