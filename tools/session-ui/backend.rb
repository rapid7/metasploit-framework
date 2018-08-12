require 'sinatra/base'
require 'json'


module Sinatra
  module Backend
    class Server
      class << self

        def setup(framework_obj,sid)
          @framework = framework_obj
          @client=framework_obj.sessions.get(sid)
        end

        def get_post
          string=@framework.post.keys
          output = {}
          count = 0
          string.each do |element|
            str=element.to_s.split("/")
            if str.length == 2
              output.each do |key,value|
                if str[0]== key
                  count +=1
                end
              end
              if count == 0
                output.store(str[0],value=[])
              end
              count=0
              output.each do |key,value|
                if str[0]==key
                  if value.empty?
                    value.push(str[1])
                  else
                    value.each do |val|
                      if val == str[1]
                        count +=1
                      end
                    end
                    if count ==0
                      value.push(str[1])
                    end
                    count=0
                  end
                end
              end
            elsif str.length == 3
              output.each do |key,value|
                if key==str[0]
                  count+=1
                end
              end
              if count == 0
                output.store(str[0],value={})
              end
              count = 0
              output.each do |key,value|
                if str[0]==key
                  if value.empty?
                    value.store(str[1],value=[])
                  else
                    value.each do |value1,component|
                      if value1==str[1]
                        count +=1
                      end
                    end
                    if count==0
                      value.store(str[1],value=[])
                    end
                    count=0
                  end
                end
              end
              output.each do|key,value|
                if key == str[0]
                  value.each do |value1,component|
                    if value1==str[1]
                      if component.empty?
                        component.push(str[2])
                      else
                        component.each do|comp|
                          if comp == str[2]
                            count +=1
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
          end
          output.to_json
        end

        def extension
          output = {}
          @client.console.dispatcher_stack.each do|dispatch|
            name=dispatch.name
            output[name] =dispatch.commands.keys
          end
          output.to_json
        end

        def session_info
          info=@client.sys.config.sysinfo(refresh: true)
          info["session_type"]=@client.session_type
          info["getuid"]=@client.sys.config.getuid
          info.to_json
        end

        def postmodule_info(*args)
          args.each do |name|
            mod=@framework.modules.create(name)
            if mod==nil
              return "Invalid module #{name}"
            else
              return Msf::Serializer::Json.dump_post_module(mod)
            end
          end
        end

        def extension_help(cmd)
          info=[]
          @client.console.dispatcher_stack.each do|dispatch|
            info.push(dispatch.commands[cmd])
          end
          return info
        end


        def execute_script(script,s)
           @client.run_cmd(script,s)
        end

        def run_exten_cmd
          #run Extension commands
        end

      end
    end
  end
  helpers Backend
end
