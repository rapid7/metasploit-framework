#This feature contains scenarios that test different handlers within the metasploit framework
@announce

Feature: As a MS Framework User
	I want to launch various handlers
	So the framework can properly handle input and output from exploits 

Scenario: Launching the exploit multi handler in Check mode
	When I run `./msfcli exploit/multi/handler C`
	Then the output should contain "module tree"
	Then the output should contain "This exploit does not support check."

Scenario: Launching the generic multi handler in Check mode
	When I run `./msfcli multi/handler C`
        Then the output should contain "module tree"
        Then the output should contain "This exploit does not support check."

 

