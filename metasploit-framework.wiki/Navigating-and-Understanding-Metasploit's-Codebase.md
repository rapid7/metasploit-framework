One of the most important things to learn when first working with Metasploit is how to navigate Metasploit's codebase. However, its often not immediately clear how this should be done. This page aims to explain some of the different approaches that one can take when navigating Metasploit's codebase and provides a primer for learning how Metasploit's codebase is structured.

A quick reminder before we get started, but one can always access the Metasploit Slack at <https://metasploit.slack.com/>. Normally this page should allow you to sign up, however if for any reason you cannot, feel free to shoot an email to msfdev *at* rapid7 *dot* com and we will be happy to send you an invite link.

Metasploit Code Structure
------------------------
A great outline of Metasploit's code structure can be found at <https://www.offensive-security.com/metasploit-unleashed/metasploit-architecture/>, which should be referred to for an overview of Metasploit's code structure. To repeat what is said there there are the following main subdirectories:

* **data** - Our general data storage area. Used to store wordlists for use by modules, binaries that are used by exploits, images, and more.
* **db** - Holds the Metasploit module database information. The `modules_metadata_base.json` file here gets updated every time a new module is pushed into the framework or the properties of one gets updated, so that Metasploit can do things like autocompleting module names.
* **docker** - Files related to building a docker instance of Metasploit Framework.
* **documentation** - This is the documentation directory. Every module that has been landed within the last 3-4 years is required to have documentation along with the exploit code. You may find older exploits do not have documentation; if you'd like to help out with this we have an open task at <https://github.com/rapid7/metasploit-framework/issues/12389> for adding missing documentation to some auxiliary modules.
* **external** - Used as a storage area for the source code of the binaries that modules might depend on, as well as burpsuite, zsh tab completion, and a Metasploit specific fork of the serialport project.
* **lib** - Where all the library code goes. If your working on something that could affect multiple modules, that code will likely be contained in a library stored under this directory.
* **modules** - All modules are stored under this directory, and are further broken down into several categories.
* **modules/exploit** - Stores exploit modules which generally tend to gain you a shell of some sort.
* **modules/auxiliary** - Stores auxiliary modules, which are used to gain information and generally don't gain a shell.
* **modules/post** - Stores post modules which perform useful actions after one has gained access to a target.
* **modules/encoders** - Stores encoder modules which are used to encode various payloads to help avoid bad characters or provide additional obfuscation.
* **modules/evasion** - Stores evasion modules which are used to help avoid antivirus.
* **modules/nops** - Stores NOP modules used for generating NOP shellcode for various architectures.
* **plugins** - Used for storing various Metasploit plugins that allow Metasploit to integrate with other programs or import data from other programs.
* **scripts** - Stores various scripts used within Metasploit, such as Meterpreter, and scripts for the console interface of Metasploit Framework.
* **spec** - Contains various RSpec checks that are used to ensure libraries and core functionality within the framework are working as expected. If you are writing a new library or adjusting one, you may need to update the corresponding RSpec file within this directory to ensure the specification checks are updated to reflect the new behavior.
* **test** - Contains tests for various parts of Metasploit code to ensure they are operating as expected.
* **tools** - Contains various tools that may be helpful under different situations. The `dev` directory contains tools useful during development, such as `tools/dev/msftidy_docs.rb` which helps ensure your documentation is in line with standards.


GitHub Code Navigation
------------------------
You can search through the code of Metasploit using GitHub with searches such as <https://github.com/rapid7/metasploit-framework/search?l=Ruby&q=%22payload.arch%22&type=code>. Note that double quotes are required to match specifically on a certain term; in the previous example this term was `payload.arch`. You can also set the `type=code` parameter to specifically match only on code results, however this can be set to `commits` or `issues` if you want to search commits or issues instead. Finally notice that when searching code, its important to also specify the language of the files you want to match. In the case above I made it so that my results would only match on files deemed by GitHub to contain Ruby code, however you can also specify other languages such as Batch, or C if you want those languages instead. You can even remove the language restriction if you find your search results are too narrow.

Another incredibly useful feature of GitHub is the ability to search across all repositories that an organization owns. This is especially useful in Metasploit as certain components, such as Rex code and payload code, may be contained in repositories other than `metasploit-framework`. To search across the public repositories that Rapid7 owns, use a search such as <https://github.com/search?q=org%3Arapid7+%22payload.arch%22&type=code>. Note the presence of the `org:rapid7` tag within the previous URL: this tells GitHub to look through all repositories that Rapid7 owns for the term `payload.arch` within any code files.

Experiment with these results and play around with GitHub searches more. Over time you will learn where it is useful and where it has its limitations and will be able to determine when it might be better to use an IDE to help understand a piece of code more.

IDE Code Navigation
------------------------
One of the best ways to navigate the codebase within Metasploit is to use RubyMine, available from <https://www.jetbrains.com/ruby/>. Whilst it is a paid tool, it offers a variety of neat referencing finding features such as the ability to right click on a method name and select `Find Usages`, or to right click the method name and select `Go To -> Declaration or Usages` to find all the locations where that method might of been defined within the codebase, which can make tracing complex definitions that wind between library and module code much easier. RubyMine also offers autocompletion and integrates well with many tools such as Git to allow you to quickly switch branches and RuboCop to help provide suggestions on where your code style could be improved.

For a cheaper option one can also use VS Code. Note however that VS Code does not have the best autotab completion and will not allow you to trace references, however if your willing to put up with this, it is a much faster and more lightweight product than RubyMine, which makes it great for those times when you just need to edit a piece of code without loading a bunch of related files that you don't need to reference or edit. It also has great regex search features that work much faster than RubyMine, allowing you to search for items within the codebase a lot quicker than you can with RubyMine, which will often seem to stutter at times due to its larger overhead.

Ultimately though the tool that you pick should be up to you. Some may prefer to work with vim/nano/emacs or some other command line editor over a GUI interface. Use whatever you can afford and feels comfortable to you!

Pry Debugging
------------------------
Occasionally, simply reading through Metasploit code may not be helpful. You need to actually get into the weeds and learn what a piece of code is doing. In these cases, it may be helpful to use `pry`, a Ruby Debugger that can be launched at a specific place within your code and which allows you to view the state of the program at that time, make adjustments as needed, and then either step through the program or continue to let it run. A full tutorial on Pry will not be provided here, instead readers are encouraged to read up on the various guides on Pry available online, such as <https://learn.co/lessons/debugging-with-pry>
