## Intro

This is a compiled shared object file of redis module.

## Load redis extension

```
MODULE load ./exp.so
```

## Run command

```
redis-cli
127.0.0.1:6379> shell.exec "whoami"
```
## Compile

You can modify the exp.c source code if you want.
And the compile it to exp.so in current directory.
```
make
```
