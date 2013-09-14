#This is the step definition file for cucumber features relating to the framework handler feature

  Given /^I launch the exploit multi handler$/ do
	steps %Q{
	
		When I run `./msfcli exploit/multi/handler E`
		Then the output should contain "Please wait while we load the module tree..."
		Then the output should contain "Started reverse handler on"
		Then the output should contain "Starting the payload handler..."

	}
  end

Given /^I launch the generic multi handler$/ do
        steps %Q{

                When I run `./msfcli multi/handler E`
                Then the output should contain "Please wait while we load the module tree..."
                Then the output should contain "Started reverse handler on"
                Then the output should contain "Starting the payload handler..."

        }
  end
