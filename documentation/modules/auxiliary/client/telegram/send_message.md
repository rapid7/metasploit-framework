The ```auxiliary/client/telegram/send_message``` module allows you to send a telegram message to given chat ID with given telegram bot token. This module also can be used as a notifier for established sessions with using the `AutoRunScript` handler option.

## Module Options

**BOT TOKEN**

Each telegram bot is given a unique authentication token when it is created. The token looks something like `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`, You can learn about obtaining tokens and generating new ones in [this document](https://core.telegram.org/bots#6-botfather).

```
set BOT_TOKEN 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
```

**CHAT ID**

Unique identifier for a chat. Chat ID can be obtained using `getUpdates` method on bot API.
`https://api.telegram.org/bot<token>/getUpdates`

```
set CHAT_ID 123456789
```

**MSG**

The message content.
```
set MSG "New meterpreter session has opened !"
```

**FORMATTING**

The Bot API supports basic formatting for messages. You can use bold, italic, underlined and strikethrough text, as well as inline links and pre-formatted code in your bots' messages. Telegram clients will render them accordingly. You can use either markdown-style or HTML-style formatting.

```
set FORMATTING Markdown
```

And you're good to go.

## Demonstration

```
msf5 > use auxiliary/client/telegram/send_message
msf5 post(client/telegram/send_message) > set BOT_TOKEN 851676320:AAFAkVtZP5Hd8cmfFIUg6j4eWJndDtdksl4
BOT_TOKEN => 851676320:AAFAkVtZP5Hd8cmfFIUg6j4eWJndDtdksl4
msf5 post(client/telegram/send_message) > set ChaT_ID 123456789
ChaT_ID => 123456789
msf5 auxiliary(client/telegram/send_message) > run

[+] Message sent
[*] Auxiliary module execution completed
```
