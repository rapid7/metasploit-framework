require './server'

puts "Running server, Please wait"
run Getdata


=begin
while sid && method== 'web_ui'
        session = verify_session(sid)
        if session
          if session.respond_to?(:response_timeout)
            last_known_timeout = session.response_timeout
            session.response_timeout = response_timeout
          end
          print_status("Starting interaction with #{session.name}...\n") unless quiet
          begin
            self.active_session = session
            sid = session.interact(driver.input.dup, driver.output)
            self.active_session = nil
            driver.input.reset_tab_completion if driver.input.supports_readline
          ensure
            if session.respond_to?(:response_timeout) && last_known_timeout
              session.response_timeout = last_known_timeout
            end
          end
        else
          sid = nil
        end
      end
=end
