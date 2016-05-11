@boot
Feature: `msfconsole` `database.yml`

  In order to connect to the database in `msfconsole`
  As a user calling `msfconsole` from a terminal
  I want to be able to set the path of the `database.yml` in one of 4 locations (in order of precedence):

  1. An explicit argument to the `-y` flag to `msfconsole`
  2. The MSF_DATABASE_CONFIG environment variable
  3. The user's `~/.msf4/database.yml`
  4. `config/database.yml` in the metasploit-framework checkout location.

  Scenario: With all 4 locations, --yaml wins
    Given a file named "command_line.yml" with:
      """
      test:
        adapter: postgresql
        database: command_line_metasploit_framework_test
        username: command_line_metasploit_framework_test
      """
    And a file named "msf_database_config.yml" with:
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
    And the project "database.yml" exists with:
      """
      test:
        adapter: postgresql
        database: project_metasploit_framework_test
        username: project_metasploit_framework_test
      """
    When I run `msfconsole -q --defer-module-loads --environment test --execute-command exit --yaml command_line.yml`
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
    And the project "database.yml" exists with:
      """
      test:
        adapter: postgresql
        database: project_metasploit_framework_test
        username: project_metasploit_framework_test
      """
    When I run `msfconsole -q --defer-module-loads --environment test --execute-command exit`
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
    And the project "database.yml" exists with:
      """
      test:
        adapter: postgresql
        database: project_metasploit_framework_test
        username: project_metasploit_framework_test
      """
    When I run `msfconsole -q --defer-module-loads --environment test --execute-command exit`
    Then the output should contain "user_metasploit_framework_test"

  Scenario: Without --yaml, MSF_DATABASE_CONFIG or ~/.msf4/database.yml, project "database.yml" wins
    Given I unset the environment variables:
      | variable            |
      | MSF_DATABASE_CONFIG |
    And a directory named "home"
    And I cd to "home"
    And a mocked home directory
    And I cd to "../.."
    And the project "database.yml" exists with:
      """
      test:
        adapter: postgresql
        database: project_metasploit_framework_test
        username: project_metasploit_framework_test
      """
    When I run `msfconsole -q --defer-module-loads --environment test --execute-command db_status --execute-command exit`
    Then the output should contain "project_metasploit_framework_test"


  Scenario: Without --yaml, MSF_DATABASE_CONFIG, ~/.msf4/database.yml, or project "database.yml", no database connection
    Given I unset the environment variables:
      | variable            |
      | MSF_DATABASE_CONFIG |
    And a directory named "home"
    And I cd to "home"
    And a mocked home directory
    And I cd to "../.."
    And the project "database.yml" does not exist
    When I run `msfconsole -q --defer-module-loads --environment test --execute-command db_status --execute-command exit`
    Then the output should not contain "command_line_metasploit_framework_test"
    And the output should not contain "environment_metasploit_framework_test"
    And the output should not contain "user_metasploit_framework_test"
    And the output should not contain "project_metasploit_framework_test"
    And the output should contain "[*] postgresql selected, no connection"

  Scenario: Starting `msfconsole` with a valid database.yml
    When I run `msfconsole -q --defer-module-loads --execute-command db_status --execute-command exit`
    Then the output should contain "[*] postgresql connected to metasploit_framework_test"

