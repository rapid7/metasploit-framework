# What is CRandomizer

CRandomizer is an obfuscation feature in Metasploit Framework that allows you to randomize C code from source. It is done by injecting random statements such as native API calls, custom fake function calls, or other routines, etc. The CRandomizer is also supported by Metasploit Framework's code compiling API, which allows you to build a custom application that is unique (in terms of checksums), also harder to reverse-engineer.

The randomness of the modification is based on a weight, an arbitrary number from 0 - 100. The higher the number, the more random the code gets.

# Components

CRandomizer relies on Metasm to be able to parse C code. The following components are built to parse and modify the source code.

## Code Factory

Also known as `Metasploit::Framework::Obfuscation::CRandomizer::CodeFactory`.

The `CodeFactory` module is used to make the random stubs that will get injected later in the source code. Currently, the things this class is capable of making include small stubs like if statements, a switch, fake functions, and Windows API calls, etc. Each stub tends to be small, and considered as benign by most AVs.

Every class in CodeFactory, except for Base, FakeFunction, and FakeFunctionCollection, is a stub candidate that gets randomly selected and used in the source code. 

If a stub requires a native API call, then the class can specify `@dep` to set that dependency. If the source code does not support the API call, then the next stub candidate is used (or until one is found).

For example, the `CRandomizer::CodeFactory::OutputDebugString` class is used to generate a fake OutputDebugString call, and the dependency is set as `['OutputDebugString']`. If the source code includes the Windows.h header, the CRandomizer knows it is okay to inject OutputDebugString. If not, CRandomizer will not use it.

## Modifier

Also known as `Metasploit::Framework::Obfuscation::CRandomizer::Modifier`.

The Modifier class decides how something should be modified, and actually modifies the source code, for example: a function, different if statements, loops, nested blocks, etc.

While the modifier walks through the source, it will randomly inject extra code (provided by the CodeFactory class) at each statement, until there are no more functions to modify.

## Parser

## Utility

# Code Example