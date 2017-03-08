The ```auxiliary/client/mms/send_mms``` module allows you to send a malicious attachment to a
collection of phone numbers of the same carrier.

In order to use this module, you must set up your own SMTP server to deliver messages. Popular
mail services such as Gmail, Yahoo, Live should work fine.

## Module Options

**CELLNUMBERS**

The 10-digit phone number (or numbers) you want to send the MMS text to. If you wish to target
against multiple phone numbers, ideally you want to create the list in a text file (one number per
line), and then load the CELLNUMBERS option like this:

```
set CELLNUMBERS file:///tmp/att_phone_numbers.txt
```

Remember that these phone numbers must be the same carrier.

**MMSCARRIER**

The carrier that the targeted numbers use. See **Supported Carrier Gateways** to learn more about
supported carriers.

**TEXTMESSAGE**

The text message you want to send. For example, this will send a text with a link to google:

```
set TEXTMESSAGE "Hi, please go: google.com"
```

The link should automatically be parsed on the phone and clickable.

**MMSFILE**

The attachment to send in the message.

**MMSFILECTYPE**

The content type to use for the attachment. Commonly supported ones include:

* audio/midi
* image/jpeg
* image/gif
* image/png
* video/mp4

To find more, please try this [list](http://www.freeformatter.com/mime-types-list.html)

**SMTPADDRESS**

The mail server address you wish to use to send the MMS messages.

**SMTPPORT**

The mail server port. By default, this is ```25```.

**SMTPUSERNAME**

The username you use to log into the SMTP server.

**SMTPPASSWORD**

The password you use to log into the SMTP server.

**SMTPFROM**

The FROM field of SMTP. In some cases, it may be used as ```SMTPUSER```. Some carriers require this
in order to receive the text, such as AT&T.

**MMSSUBJECT**

The MMS subject. Some carriers require this in order to receive the text, such as AT&T.

## Supported Carrier Gateways

The module supports the following carriers:

* AT&T
* Sprint
* T-Mobile
* Verizon
* Google Fi

## Finding the Carrier for a Phone Number

Since you need to manually choose the carrier gateway for the phone numbers, you need to figure out
how to identify the carrier of a phone number. There are many services that can do this, such as:

http://freecarrierlookup.com/

## Gmail SMTP Example

Gmail is a popular mail server, so we will use this as a demonstration.

Assuming you are already using two-factor authentication, you need to create an [application password](https://support.google.com/accounts/answer/185833?hl=en).

After creating the application password, configure auxiliary/client/mms/send_mms this way:

* ```set cellnumbers [PHONE NUMBER]```
* ```set mmscarrier [CHOOSE A SUPPORTED CARRIER]```
* ```set textmessage "[TEXT MESSAGE]"```
* ```set smtpaddress smtp.gmail.com```
* ```set smtpport 587```
* ```set mmsfile /tmp/example.mp4```
* ```set mmsfilectype video/mp4```
* ```set smtpusername [USERNAME FOR GMAIL]``` (you don't need ```@gmail.com``` at the end)
* ```set smtppassword [APPLICATION PASSWORD]```

And you should be ready to go.

## Yahoo SMTP Example

Yahoo is also a fairly popular mail server (although much slower to deliver comparing to Gmail),
so we will demonstrate as well.

Before using the module, you must do this to your Yahoo account:

1. Sign in to Yahoo Mail.
2. [Go to your "Account security" settings.](https://login.yahoo.com/account/security#less-secure-apps)
3. Turn on Allow apps that use less secure sign in.

After configuring your Yahoo account, configure auxiliary/client/mms/send_mms this way:

* ```set cellnumbers [PHONE NUMBER]```
* ```set mmscarrier [CHOOSE A SUPPORTED CARRIER]```
* ```set textmessage "[TEXT MESSAGE]"```
* ```set smtpaddress smtp.mail.yahoo.com```
* ```set smtpport 25```
* ```set mmsfile /tmp/example.mp4```
* ```set mmsfilectype video/mp4```
* ```set smtpusername [USERNAME FOR YAHOO]@yahoo.com```
* ```set smtppassword [YAHOO LOGIN PASSWORD]```

And you're good to go.

## Demonstration

After setting up your mail server and the module, your output should look similar to this:

```
msf auxiliary(send_mms) > run

[*] Sending mms message to 1 number(s)...
[*] Done.
[*] Auxiliary module execution completed
msf auxiliary(send_mms) > 
```
