require 'metasploit/framework/data_service/remote/msf_red/job_handler'

class MessageJobHandler
  include JobHandler

  JOB_HANDLED = 'message'

  def handle(message_hash)
    message = "User: #{message_hash['user_id']}, #{message_hash['message']}"
    banner = "*" * message.size
    puts "\n"
    puts "\n"
    puts banner
    puts message
    puts banner
    puts "\n"
  end

  def job_type_handled
    JOB_HANDLED
  end

end