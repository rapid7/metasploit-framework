@boot
Feature: Launching `msfconsole`

  @no-database-yml
  Scenario: Starting `msfconsole` without a database.yml
    Given I run `msfconsole` interactively
    And I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"
    When I type "db_status"
    And I type "exit"
    Then the output should contain "[*] postgresql selected, no connection"
  
  @no-database-yml
  Scenario: Starting `msfconsole` with an invalid database.yml
    Given a file named "database.yml" with:
      """
      development: &pgsql
        adapter: postgresql
        database: metasploit_framework_development
        username: postgres
        port: 6543
        pool: 5
        timeout: 5
      production:
        <<: *pgsql
      test:
        <<: *pgsql
        database: metasploit_framework_test
      """
    Given I run `msfconsole -y database.yml` interactively
    And I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"
    When I type "db_status"
    And I type "exit"
    Then the output should contain "[-] Failed to connect to the database: could not connect to server"
    Then the output should contain "[*] postgresql selected, no connection"
  
  Scenario: Starting `msfconsole` with a valid database.yml
    Given I run `msfconsole` interactively
    And I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"
    When I type "db_status"
    And I type "exit"
    Then the output should contain "[*] postgresql connected to metasploit_framework_test"
  
  
  
  
  
  