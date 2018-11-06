# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

module Dnsruby
  #  Takes care of the validation for the SelectThread. If queries need to be
  #  made in order to validate the response, then a separate thread is fired up
  #  to do this.
  class ValidatorThread # :nodoc: all
    #     include Singleton
    def initialize(*args)
      @client_id, @client_queue, @response, @error, @query, @st, @res = args
      #  Create the validation thread, and a queue to receive validation requests
      #  Actually, need to have a thread per validator, as they make recursive calls.
      #       @@mutex = Mutex.new
      #       @@validation_queue = Queue.new
      #       @@validator_thread = Thread.new{
      #         do_validate
      #       }
    end
    def run
      #  ONLY START THE NEW THREAD IF VALIDATION NEED OCCUR!!
      if (should_validate)
        Thread.new{
          do_validate
        }
      else
        do_validate
      end
    end


    #     def add_to_queue(item)
    #       print "ADding to validator queue\n"
    # #      @@mutex.synchronize{
    #         @@validation_queue.push(item)
    # #      }
    #     end
    def do_validate
      #       while (true)
      #         item = nil
      #         print "Waiting to pop validation item\n"
      # #        @@mutex.synchronize{
      #           item = @@validation_queue.pop
      # #        }
      #       print "Popped validation request\n"
      #         client_id, client_queue, response, err, query, st, res = item
      validated_ok = validate(@query, @response, @res)

      validated_ok = false if (@error && !(NXDomain === @error))

      cache_if_valid(@query, @response)

      #  Now send the response back to the client...
      #       print "#{Time.now} : Got result for #{@query.question()[0].qname}, #{@query.question()[0].qtype}\n"
      if (validated_ok)
        @st.push_validation_response_to_select(@client_id, @client_queue, @response, nil, @query, @res)
      else
        @st.push_validation_response_to_select(@client_id, @client_queue, @response,
          @response.security_error, @query, @res)
      end


      #       end
    end


    def should_validate
      return ValidatorThread.requires_validation?(@query, @response, @error, @res)
    end

    def ValidatorThread.requires_validation?(query, response, error, res)
      #  @error will be nil for DNS RCODE errors - it will be true for TsigError. really?!
      if ((!error || (error.instance_of?NXDomain)) && query.do_validation)
        if (res.dnssec)
          if (response.security_level != Message::SecurityLevel.SECURE)
            return true
          end
        end
      end
      return false

    end

    def validate(query, response, res)
      if (should_validate)
        begin
          #  So, we really need to be able to take the response out of the select thread, along
          #  with the responsibility for sending the answer to the client.
          #  Should we have a validator thread? Or a thread per validation?
          #  Then, select thread gets response. It performs basic checks here.
          #  After basic checks, the select-thread punts the response (along with queues, etc.)
          #  to the validator thread.
          #  The validator validates it (or just releases it with no validation), and then
          #  sends the request to the client via the client queue.
          Dnssec.validate_with_query(query,response)
          return true
        rescue VerifyError => e
          response.security_error = e
          response.security_level = BOGUS
          #  Response security_level should already be set
          return false
        end
      end
      return true
    end

    def cache_if_valid(query, response)
      return if @error
      PacketSender.cache(query, response)
    end
  end
end
