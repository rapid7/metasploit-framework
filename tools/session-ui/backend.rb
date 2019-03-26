# This class provides methods that fetch data from metasploit api's and format it in a way that is readable by the front end javascript
# support library.

require 'sinatra/base'
require 'singleton'

# TODO : use singleton method here so that only one instance of the server is made rather when the class is invoked multiple times.
# The idea is to launch a server class only once with the corresponding session ID.

class ServerMethods
  class << self

    def server_setup(framework_obj, sid)
      @framework = framework_obj
      @client = framework_obj.sessions.get(sid)

      # setting the Output interface
      @output = Rex::Ui::Text::Output::Buffer.new
      @output.extend Rex::Ui::Text::Output::Buffer::Stdout
    end

    # This function will return list of post modules in json format
    def get_post
      string = @framework.post.keys
      output = {}
      count = 0
      string.each do |element|
        str = element.to_s.split("/")
        if str.length == 2
          output.each do |key, value|
            if str[0] == key
              count += 1
            end
          end
          if count == 0
            output.store(str[0], value = [])
          end
          count = 0
          output.each do |key, value|
            if str[0] == key
              if value.empty?
                value.push(str[1])
              else
                value.each do |val|
                  if val == str[1]
                    count += 1
                  end
                end
                if count == 0
                  value.push(str[1])
                end
                count = 0
              end
            end
          end
        elsif str.length == 3
          output.each do |key, value|
            if key == str[0]
              count += 1
            end
          end
          if count == 0
            output.store(str[0], value = {})
          end
          count = 0
          output.each do |key, value|
            if str[0] == key
              if value.empty?
                value.store(str[1], value = [])
              else
                value.each do |value1, component|
                  if value1 == str[1]
                    count += 1
                  end
                end
                if count == 0
                  value.store(str[1], value = [])
                end
                count = 0
              end
            end
          end
          output.each do |key, value|
            next unless key == str[0]

            value.each do |value1, component|
              if value1 == str[1]
                if component.empty?
                  component.push(str[2])
                else
                  component.each do |comp|
                    if comp == str[2]
                      count += 1
                    end
                  end
                  if count == 0
                    component.push(str[2])
                  end
                  count = 0
                end
              end
            end
          end

        end
      end
      output.to_json
    end

    # This script will return Extension commands available in active session ID
    def extension
      output = {}
      output1 = {}
      static_count = 0
      @client.console.dispatcher_stack.each do |dispatch|
        if dispatch.name.include? ": "
          output.each do |key, value| # Creation of new keys
            if dispatch.name.to_s.split(": ")[0] == key
              static_count += 1
            end
          end
          if static_count == 0
            output.store(dispatch.name.to_s.split(": ")[0], value = {})
          end
          static_count = 0
          output.each do |key, value|
            if key == dispatch.name.to_s.split(": ")[0]
              value.store((dispatch.name.to_s.split(': ')[1]).to_s, component = dispatch.commands.keys)
            end
          end
        else
          output1.store(dispatch.name.to_s.to_s, value = dispatch.commands.keys)
        end
      end
      output1 = output.merge(output1).to_json
      return output1
    end

    def session_info
      info = @client.sys.config.sysinfo(refresh: true)
      info["session_type"] = @client.session_type
      info["getuid"] = @client.sys.config.getuid
      info.to_json
    end

    def postmodule_info(*args)
      return_output = {}
      args.each do |name|
        mod = @framework.modules.create(name)
        if mod.nil?
          return "Invalid module #{name}"
        else
          return_output = {
            info: Msf::Serializer::Json.dump_post_module(mod),
            options: Msf::Serializer::ReadableText.dump_options(mod, '  '),
            advance_option: Msf::Serializer::ReadableText.dump_advanced_options(mod, '  ')
          }
        end
      end
      return_output.to_json
    end

    def extension_help(cmd)
      info = []
      @client.console.dispatcher_stack.each do |dispatch|
        info.push(dispatch.commands[cmd])
      end
      info.to_json
    end

    def execute_script(script)
      @client.run_cmd(script, @output)
      @output.dump_buffer.to_json
    end

  end
end