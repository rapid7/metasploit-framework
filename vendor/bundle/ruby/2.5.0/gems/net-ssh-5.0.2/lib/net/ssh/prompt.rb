require 'io/console'

module Net 
  module SSH

    # Default prompt implementation, called for asking password from user.
    # It will never be instantiated directly, but will instead be created for
    # you automatically.
    #
    # A custom prompt objects can implement caching, or different UI. The prompt
    # object should implemnted a start method, which should return something implementing
    # ask and success. Net::SSH uses it like:
    #
    #   prompter = options[:password_prompt].start({type:'password'})
    #   while !ok && max_retries < 3
    #     user = prompter.ask("user: ", {}, true)
    #     password = prompter.ask("password: ", {}, false)
    #     ok = send(user, password)
    #     prompter.sucess if ok
    #   end
    #
    class Prompt
      # factory
      def self.default(options = {})
        @default ||= new(options)
      end
  
      def initialize(options = {}); end
  
      # default prompt object implementation. More sophisticated implemenetations
      # might implement caching.
      class Prompter
        def initialize(info)
          if info[:type] == 'keyboard-interactive'
            $stdout.puts(info[:name]) unless info[:name].empty?
            $stdout.puts(info[:instruction]) unless info[:instruction].empty?
          end
        end
  
        # ask input from user, a prompter might ask for multiple inputs
        # (like user and password) in a single session.
        def ask(prompt, echo=true)
          $stdout.print(prompt)
          $stdout.flush
          ret = $stdin.noecho(&:gets).chomp
          $stdout.print("\n")
          ret
        end
  
        # success method will be called when the password was accepted
        # It's a good time to save password asked to a cache.
        def success; end
      end
  
      # start password session. Multiple questions might be asked multiple times
      # on the returned object. Info hash tries to uniquely identify the password
      # session, so caching implementations can save passwords properly.
      def start(info)
        Prompter.new(info)
      end
    end

  end
end
