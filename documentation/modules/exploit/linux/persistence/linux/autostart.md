## Autostart persistence

This module persist a payload by creating a `.desktop` entry for Linux desktop targets.

### Testing

1. Exploit a box
2. `use exploit/linux/local/autostart_persistence`
3. `set SESSION <id>`
4. `set PAYLOAD cmd/unix/reverse_python` (for instance), configure the payload as needed
5. `exploit`

When the victim logs in your payload will be executed!


### Options


**NAME**

Name of the `.desktop` entry to add, if not specified it will be chosen randomly.

