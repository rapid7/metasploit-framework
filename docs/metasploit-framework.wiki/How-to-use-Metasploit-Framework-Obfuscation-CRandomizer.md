# How to use Metasploit::Framework::Obfuscation::CRandomizer

## What is CRandomizer

CRandomizer is an obfuscation feature in Metasploit Framework that allows you to randomize C code. It is done by injecting random statements such as native API calls, custom fake function calls, or other routines, etc. The CRandomizer is also supported by Metasploit Framework's code compiling API, which allows you to build a custom application that is unique (in terms of checksums), also harder to reverse-engineer.

The randomness of the modification is based on a weight, an arbitrary number from 0 - 100. The higher the number, the more random the code gets.

## Components

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

Also known as `Metasploit::Framework::Obfuscation::CRandomizer::Parser`.

The main purpose of the Parser class is to convert the source code into a parsable format using Metasm, and then pass the functions to the Modifier class to process.

## Utility

The Utility class provides quick-to-use methods that any CRandomizer classes could use.

# Code Example

## Creating a new stub

First, add a new file under the code_factory with an arbitrary file name. For example: hello.rb. In this example, let's create a new stub that will printf() "Hello World". Your stub should be written as a class under the CodeFactory namespace, and make sure to inherit the Base class. Like this:

```ruby
require 'metasploit/framework/obfuscation/crandomizer/code_factory/base'

module Metasploit
  module Framework
    module Obfuscation
      module CRandomizer
        module CodeFactory

          class Printf < Base
            def initialize
              super
              @dep = ['printf']
            end

            def stub
              %Q|
              int printf(const char*);
              void stub() {
                printf("Hello World");
              }|
            end
          end

        end
      end
    end
  end
end
```

Notice a couple of things:

* Every class should have its own `stub` method. And this `stub` method should return a string that contains the code you wish to inject. In addition, your code should be written as a function so that Metasm knows how to pick it up, hence the printf is in a `void stub()` function.
* If your stub requires a native API (in this case, we are using `printf`), then you must add this function name in the `@dep` instance variable, which is an array.
* Please keep in mind that your stub should remain simple and small, and not unique. For example, avoid:
  * Allocate a huge chunk of memory
  * Avoid marking or allocating executable memory
  * Loops
  * Load referenced section, resource, or .data
  * Anti-debugging functions from the Windows API
  * Lots of function calls
  * Unique strings
  * APIs that access the Windows registry or the file system
  * XOR
  * Shellcode
  * Any other suspicious code patterns that are unique to malware.

## Randomizing source code

Please refer to tools/exploit/random_compile_c.rb for example.
