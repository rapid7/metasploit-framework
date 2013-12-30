class Metasploit::Framework::Command::Check::Simple < Metasploit::Framework::Command::Base
  include Metasploit::Framework::Command::Child

  #
  # Validations
  #

  #
  # Attribute Validations
  #

  validates :dispatcher,
            fanged: true
  validates :metasploit_instance,
            presence: true
  validates :module_type,
            inclusion: {
                in: [
                    'exploit'
                ]
            }
  validates :words,
            length: {
                is: 0
            }

  #
  # Methods
  #

  delegate :metasploit_instance,
           allow_nil: true,
           to: :dispatcher

  delegate :module_type,
           allow_nil: true,
           to: :metasploit_instance

  protected

  def run_with_valid
    begin
      code = metasploit_instance.check_simple(
          'LocalInput'  => dispatcher.input,
          'LocalOutput' => dispatcher.output
      )
    # rescue Interrupt before all exceptions so user can exit long checks with Ctrl+C
    rescue Interrupt => interrupt
      raise interrupt
    # have to catch all Exception because it's calling user code that could be raise any error while under development
    rescue ::Exception => exception
      print_error("Exploit check failed: #{exception.class} #{exception}")

      unless exception.is_a? Msf::OptionValidateError
        print_error("Call stack:")

        exception.backtrace.each do |line|
          if line =~ /lib.msf.base.simple/
            break
          end

          print_error("  #{line}")
        end
      end
    else
      if code && code.is_a?(Array) && code.length > 1
        if code == Msf::Exploit::CheckCode::Vulnerable
          print_good(code[1])
        else
          print_status(code[1])
        end
      else
        print_error("Check failed: The state could not be determined.")
      end
    end
  end
end