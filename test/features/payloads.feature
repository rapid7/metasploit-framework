#This feature contains scenarios to test the ability to run/access payloads from the metasploit framework

Feature: I want access to Metasploit payloads
	So that I can define payload options for exploits

Scenario: Verify the windows shell reverse tcp payload option in ruby
	When I run msfpayload to generate a "windows/shell_reverse_tcp" on the local host
	Then the output should contain "# windows/shell_reverse_tcp"
	Then the output should contain "# http://www.metasploit.com"

Scenario: Verify the windows x64 shell reverse tcp payload option in ruby
		When I run msfpayload to generate a "windows/x64/shell_reverse_tcp" on the local host
        Then the output should contain "# windows/x64/shell_reverse_tcp"
        Then the output should contain "# http://www.metasploit.com"

Scenario: Verify the linux x86 shell reverse tcp payload option in ruby
		When I run msfpayload to generate a "linux/x86/shell_reverse_tcp" on the local host
        Then the output should contain "# linux/x86/shell_reverse_tcp"
        Then the output should contain "# http://www.metasploit.com"

Scenario: Verify the windows meterpreter reverse tcp payload can output its contents in ruby
	When I run msfpayload to generate a "windows/meterpreter/reverse_tcp" on the local host
	Then the output should contain "# windows/meterpreter/reverse_tcp - 290 bytes (stage 1)"
	Then the output should contain "# http://www.metasploit.com"
