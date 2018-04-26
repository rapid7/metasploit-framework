The following is the recommended format for module documentation.
But feel free to add more content/sections to this.
One of the general ideas behind these documents is to help someone troubleshoot the module if it were to stop
functioning in 5+ years, so giving links or specific examples can be VERY helpful.

## Vulnerable Application

  Instructions to get the vulnerable application.  If applicable, include links to the vulnerable install files,
  as well as instructions on installing/configuring the environment if it is different than a standard install.
  Much of this will come from the PR, and can be copy/pasted.

## Verification Steps

  Example steps in this format (is also in the PR):

  1. Install the application
  2. Start msfconsole
  3. Do: ```use [module path]```
  4. Do: ```run```
  5. You should get a shell.

## Options

  **Option name**

  Talk about what it does, and how to use it appropriately.  If the default value is likely to change, include the default value here.

## Scenarios

### Version of software and OS as applicable

  Specific demo of using the module that might be useful in a real world scenario.

  ```
  code or console output
  ```

  For example:

  To do this specific thing, here's how you do it:

  ```
  msf > use module_name
  msf auxiliary(module_name) > set POWERLEVEL >9000
  msf auxiliary(module_name) > exploit
  ```