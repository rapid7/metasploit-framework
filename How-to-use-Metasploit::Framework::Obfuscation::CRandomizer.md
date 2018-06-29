# What is CRandomizer

CRandomizer is an obfuscation feature in Metasploit Framework that allows you to randomize C code from source. It is done by injecting random statements such as native API calls, custom fake function calls, or other routines, etc. The CRandomizer is also supported by Metasploit Framework's code compiling API, which allows you to build a custom application that is unique (in terms of checksums), also harder to reverse-engineer.

# Components

CRandomizer relies on Metasm to be able to parse C code.

## Code Factory

## Modifier

## Parser

## Utility

# Code Example