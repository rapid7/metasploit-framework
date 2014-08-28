Feature: `msfconsole` `database.yml`

  In order to connect to the database in `msfconsole`
  As a user calling `msfconsole` from a terminal
  I want to be able to set the path of the `database.yml` in one of 4 locations (in order of precedence):

  1. An explicit argument to the `-y` flag to `msfconsole`
  2. The MSF_DATABASE_CONFIG environment variable
  3. The user's `~/.msf4/database.yml`
  4. `config/database.yml` in the metasploit-framework checkout location.

  Scenario: With all 4 locations, --yaml wins
    Given a file named "msf_database_config.yml" with:
      """
      test:
        adapter: postgresql
        database: environment_metasploit_framework_test
        username: environment_metasploit_framework_test
      """
    And I set the environment variables to:
      | variable            | value                   |
      | MSF_DATABASE_CONFIG | msf_database_config.yml |
    And a directory named "home"
    And I cd to "home"
    And a mocked home directory
    And a directory named ".msf4"
    And I cd to ".msf4"
    And a file named "database.yml" with:
      """
      test:
        adapter: postgresql
        database: user_metasploit_framework_test
        username: user_metasploit_framework_test
      """
    And I cd to "../.."
    And a file named "command_line.yml" with:
      """
      test:
        adapter: postgresql
        database: command_line_metasploit_framework_test
        username: command_line_metasploit_framework_test
      """
    When I run `msfconsole --environment test --yaml command_line.yml` interactively
    And I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"
    And I type "exit"
    Then the output should contain "command_line_metasploit_framework_test"

  Scenario: Without --yaml, MSF_DATABASE_CONFIG wins
    Given a file named "msf_database_config.yml" with:
      """
      test:
        adapter: postgresql
        database: environment_metasploit_framework_test
        username: environment_metasploit_framework_test
      """
    And I set the environment variables to:
      | variable            | value                   |
      | MSF_DATABASE_CONFIG | msf_database_config.yml |
    And a directory named "home"
    And I cd to "home"
    And a mocked home directory
    And a directory named ".msf4"
    And I cd to ".msf4"
    And a file named "database.yml" with:
      """
      test:
        adapter: postgresql
        database: user_metasploit_framework_test
        username: user_metasploit_framework_test
      """
    And I cd to "../.."
    When I run `msfconsole --environment test` interactively
    And I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"
    And I type "exit"
    Then the output should contain "environment_metasploit_framework_test"

  Scenario: Without --yaml or MSF_DATABASE_CONFIG, ~/.msf4/database.yml wins
    Given I unset the environment variables:
      | variable            |
      | MSF_DATABASE_CONFIG |
    And a directory named "home"
    And I cd to "home"
    And a mocked home directory
    And a directory named ".msf4"
    And I cd to ".msf4"
    And a file named "database.yml" with:
      """
      test:
        adapter: postgresql
        database: user_metasploit_framework_test
        username: user_metasploit_framework_test
      """
    And I cd to "../.."
    When I run `msfconsole --environment test` interactively
    And I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"
    And I type "exit"
    Then the output should contain "user_metasploit_framework_test"