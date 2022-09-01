The `auxiliary/client/telegram/send_message` module allows you to send a Telegram message and/or document to a given chat ID or
set of chat IDs with a given Telegram bot token. This module also can be used as a notifier for established sessions with
using the `AutoRunScript` handler option.

## Module Options

**BOT TOKEN**

Each Telegram bot is given a unique authentication token when it is created. The token looks like
`123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`. You can generate a new token by messaging @botfather via `https://t.me/botfather` and
sending the message `/newbot` to it, which should prompt it to ask a series of questions that will allow you to generate your bot.
Once you have completed this, you should get a message saying `Use this token to access the HTTP API:` followed by the value of the
bot's token. Use this value for `BOT_TOKEN`. If you have any issues, refer to [this document](https://core.telegram.org/bots#6-botfather).

**CHAT ID**

Unique identifier for a chat. To get the `CHAT_ID` value, send a message to the bot username that you created
earlier. Then browse to `https://api.telegram.org/bot<BOT_TOKEN VALUE>/getUpdates`
and look for a line like `"chat":"id":1344308063`. That ID is what you will
want to use the value of `CHAT_ID`; in this case it would be `1344308063`.

For group chats, add the bot to the chat, then perform these same steps and look for a line that has the text `"type":"group"`.
This should be within a pair of `{}` that contains an `id:` field. The value of this `id:` field is the value of the chat id
for the group.

**MSG**

The content of the message to be sent.

**FORMATTING**

The Bot API supports basic formatting for messages. You can use bold, italic, underlined and strikethrough text,
as well as inline links and pre-formatted code in your bots' messages. Telegram clients will render them accordingly.
You can use either markdown-style or HTML-style formatting.

**DOCUMENT**
The full path to the document to be sent.

**IDFILE**
The full path to the file which contains different CHAT_IDs, one per line, which the message and/or document will be sent to.


## Demonstration

```
msf6 > use auxiliary/client/telegram/send_message
msf6 auxiliary(client/telegram/send_message) > show options

Module options (auxiliary/client/telegram/send_message):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   BOT_TOKEN                    yes       Telegram BOT token
   CHAT_ID                      no        Chat ID for the BOT
   DOCUMENT                     no        The path to the document(binary, video etc)
   FORMATTING  Markdown         no        Message formating option (Markdown|MarkdownV2|HTML) (Accepted: Markdown, MarkdownV2, HT
                                          ML)
   IDFILE                       no        File containing chat IDs, one per line
   MESSAGE                      no        The message to be sent

msf6 auxiliary(client/telegram/send_message) > set BOT_TOKEN *redacted*
BOT_TOKEN => *redacted*
msf6 auxiliary(client/telegram/send_message) >
msf6 auxiliary(client/telegram/send_message) >
msf6 auxiliary(client/telegram/send_message) >
msf6 auxiliary(client/telegram/send_message) > set CHAT_ID 1725*redacted*
CHAT_ID => 1725*redacted*
msf6 auxiliary(client/telegram/send_message) > set DOCUMENT /home/gwillcox/git/metasploit-framework/bind_meterpreter.py
DOCUMENT => /home/gwillcox/git/metasploit-framework/bind_meterpreter.py
msf6 auxiliary(client/telegram/send_message) > set MESSAGE "Check out this cool new script!"
MESSAGE => Check out this cool new script!
msf6 auxiliary(client/telegram/send_message) > run

[+] Document sent successfully to 1725*redacted*
[+] Message sent successfully to 1725*redacted*
[*] Auxiliary module execution completed
msf6 auxiliary(client/telegram/send_message) > run

[+] Document sent successfully to 1725*redacted*
[+] Message sent successfully to 1725*redacted*
[*] Auxiliary module execution completed
msf6 auxiliary(client/telegram/send_message) > code test_ids
[*] exec: code test_ids

msf6 auxiliary(client/telegram/send_message) > set IDFILE test_ids
IDFILE => test_ids
msf6 auxiliary(client/telegram/send_message) > cat test_ids
[*] exec: cat test_ids

-593*redacted*
1725*redacted*msf6 auxiliary(client/telegram/send_message) > run

[!] Opening `/home/gwillcox/git/metasploit-framework/test_ids` to fetch chat IDs...
[+] Document sent successfully to -593*redacted*

[+] Message sent successfully to -593*redacted*

[+] Document sent successfully to 1725*redacted*
[+] Message sent successfully to 1725*redacted*
[*] Auxiliary module execution completed
msf6 auxiliary(client/telegram/send_message) >
```
