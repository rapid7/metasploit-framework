Feature: Help command
  
  Background:
    Given I run `msfconsole` interactively
    And I wait for stdout to contain "Free Metasploit Pro trial: http://r-7.co/trymsp"
    
  Scenario: The 'help' command's output
    When I type "help"
    And I type "exit"
    Then the output should contain:
      """
      Core Commands
      =============

          Command       Description
          -------       -----------
          ?             Help menu
          back          Move back from the current context
          banner        Display an awesome metasploit banner
          cd            Change the current working directory
          color         Toggle color
          connect       Communicate with a host
          edit          Edit the current module with $VISUAL or $EDITOR
          exit          Exit the console
          go_pro        Launch Metasploit web GUI
          grep          Grep the output of another command
          help          Help menu
          info          Displays information about one or more module
          irb           Drop into irb scripting mode
          jobs          Displays and manages jobs
          kill          Kill a job
          load          Load a framework plugin
          loadpath      Searches for and loads modules from a path
          makerc        Save commands entered since start to a file
          popm          Pops the latest module off the stack and makes it active
          previous      Sets the previously loaded module as the current module
          pushm         Pushes the active or list of modules onto the module stack
          quit          Exit the console
          reload_all    Reloads all modules from all defined module paths
          resource      Run the commands stored in a file
          route         Route traffic through a session
          save          Saves the active datastores
          search        Searches module names and descriptions
          sessions      Dump session listings and display information about sessions
          set           Sets a variable to a value
          setg          Sets a global variable to a value
          show          Displays modules of a given type, or all modules
          sleep         Do nothing for the specified number of seconds
          spool         Write console output into a file as well the screen
          threads       View and manipulate background threads
          unload        Unload a framework plugin
          unset         Unsets one or more variables
          unsetg        Unsets one or more global variables
          use           Selects a module by name
          version       Show the framework and console library version numbers


      Database Backend Commands
      =========================

          Command           Description
          -------           -----------
          creds             List all credentials in the database
          db_connect        Connect to an existing database
          db_disconnect     Disconnect from the current database instance
          db_export         Export a file containing the contents of the database
          db_import         Import a scan result file (filetype will be auto-detected)
          db_nmap           Executes nmap and records the output automatically
          db_rebuild_cache  Rebuilds the database-stored module cache
          db_status         Show the current database status
          hosts             List all hosts in the database
          loot              List all loot in the database
          notes             List all notes in the database
          services          List all services in the database
          vulns             List all vulnerabilities in the database
          workspace         Switch between database workspaces
      """
  