The `auxiliary/client/telegram/send_message` module allows you to send a Telegram message and document to a given chat ID with a given
Telegram bot token. This module also can be used as a notifier for established sessions with using the `AutoRunScript` handler option.
This module can also be used to send a specified document and a message to multiple users for phishing purposes.

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

**MSG**

The message content.

**FORMATTING**

The Bot API supports basic formatting for messages. You can use bold, italic, underlined and strikethrough text,
as well as inline links and pre-formatted code in your bots' messages. Telegram clients will render them accordingly.
You can use either markdown-style or HTML-style formatting.

**DOCUMENT**
The path of the document to be sent.

**IDFILE**
The path of the file which contains different CHAT_IDs, one per line.


## Demonstration

```
msf6 auxiliary(client/telegram/send_document) > show options 

Module options (auxiliary/client/telegram/send_document):

   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   BOT_TOKEN  123-94AE32:dJIEdGsNljsdf2092_fdiewSFJiei23Kq  yes       Telegram BOT token
   CHAT_ID    1234234243                                    yes       Chat ID for the BOT
   DOCUMENT   ~/Documents/document_to_send                  yes       The path to the document(binary, video etc)
   IDFILE                                                   no        File containing chat IDs, one per line
   MESSAGE    Please open this document                     no        Optional message sent with the document

msf6 auxiliary(client/telegram/send_document) > run 

[+] Document sent successfully!
[*] Auxiliary module execution completed
msf6 auxiliary(client/telegram/send_document) >
```
