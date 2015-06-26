module MsfTest
module JavameeterpeterSpecs

  ## This file is intended to be used in conjunction with a harness, 
  ## such as meeterpeter_win32_spec.rb

  def self.included(base)
        	base.class_eval do

      it "should not error when taking a screenshot" do
        success_strings = [ 'Screenshot saved to' ]
        hlp_run_command_check_output("screenshot","screenshot", success_strings)
      end
            
    end
  end

end
end
