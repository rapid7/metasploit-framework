# Overview
One of the most important things to learn when first working with Metasploit is how to navigate Metasploit's codebase. However, its often not immediately clear how this should be done. This page aims to explain some of the different approaches that one can take when navigating Metasploit's codebase and provides a primer for learning how Metasploit's codebase is structured.

A quick reminder before we get started, but one can always access the Metasploit Slack at <https://metasploit.slack.com/>. Normally this page should allow you to sign up, however if for any reason you cannot, feel free to shoot an email to msfdev *at* rapid7 *dot* com and we will be happy to send you an invite link.

# Metasploit Code Structure
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
* **tools** - Contains various tools that may be helpful under different situations. The `dev` directory contains tools useful during development, such as `tools/dev/msftidy_docs.rb` which helps ensure your documentation is in line with standards.~~

# Code Navigation Tools

## GitHub Code Navigation
You can search through the code of Metasploit using GitHub with searches such as <https://github.com/rapid7/metasploit-framework/search?l=Ruby&q=%22payload.arch%22&type=code>. Note that double quotes are required to match specifically on a certain term; in the previous example this term was `payload.arch`. You can also set the `type=code` parameter to specifically match only on code results, however this can be set to `commits` or `issues` if you want to search commits or issues instead. Finally notice that when searching code, its important to also specify the language of the files you want to match. In the case above I made it so that my results would only match on files deemed by GitHub to contain Ruby code, however you can also specify other languages such as Batch, or C if you want those languages instead. You can even remove the language restriction if you find your search results are too narrow.

Another incredibly useful feature of GitHub is the ability to search across all repositories that an organization owns. This is especially useful in Metasploit as certain components, such as Rex code and payload code, may be contained in repositories other than `metasploit-framework`. To search across the public repositories that Rapid7 owns, use a search such as <https://github.com/search?q=org%3Arapid7+%22payload.arch%22&type=code>. Note the presence of the `org:rapid7` tag within the previous URL: this tells GitHub to look through all repositories that Rapid7 owns for the term `payload.arch` within any code files.

Experiment with these results and play around with GitHub searches more. Over time you will learn where it is useful and where it has its limitations and will be able to determine when it might be better to use an IDE to help understand a piece of code more.

## SolarGraph Code Navigation
A better way to navigate code, particularly across repos, and also find out where things are defined using an easy to use interface, is SourceGraph from
<https://sourcegraph.com>. The interface is not hard to use and you can find several tutorials over at <https://docs.sourcegraph.com/tutorials> on how to use it.

The main benefit of SourceGraph over GitHub is the ability to search all known repositories at once and then easily jump between definitions using either the
online search at <https://sourcegraph.com/search>, or the GitHub integrated browser plugin from <https://docs.sourcegraph.com/integration/browser_extension> to allow
easy navigation of Metasploit and Rapid7 code from your GitHub PR reviews.

It is also recommended to review the tutorials and better understand some of the advanced search capabilities of SourceGraph as they do provide some useful search
functionality that is not available or may be harder to perform with GitHub.

# IDE Code Navigation

## RubyMine Code Navigation
One of the best ways to navigate the codebase within Metasploit is to use RubyMine, available from <https://www.jetbrains.com/ruby/>. Whilst it is a paid tool, it offers a variety of neat referencing finding features such as the ability to right click on a method name and select `Find Usages`, or to right click the method name and select `Go To -> Declaration or Usages` to find all the locations where that method might of been defined within the codebase, which can make tracing complex definitions that wind between library and module code much easier. RubyMine also offers autocompletion and integrates well with many tools such as Git to allow you to quickly switch branches and RuboCop to help provide suggestions on where your code style could be improved.

For a cheaper option one can also use VS Code. Note however that VS Code does not have the best autotab completion and will not allow you to trace references, however if your willing to put up with this, it is a much faster and more lightweight product than RubyMine, which makes it great for those times when you just need to edit a piece of code without loading a bunch of related files that you don't need to reference or edit. It also has great regex search features that work much faster than RubyMine, allowing you to search for items within the codebase a lot quicker than you can with RubyMine, which will often seem to stutter at times due to its larger overhead.

Ultimately though the tool that you pick should be up to you. Some may prefer to work with vim/nano/emacs or some other command line editor over a GUI interface. Use whatever you can afford and feels comfortable to you!

## SolarGraph Code Navigation - VSCode
We'd be remiss to not mention SolarGraph as a potential plugin that one can use to navigate code within VSCode. This tool
provides a lot of the autocomplete and IntelliSense functionality you might get from dedicated IDEs such as RubyMine, within
VSCode itself. The tool can be installed by running `gem install solargraph-rails` for the Rails integrations, which will
also in turn install `solargraph` itself. If you just want SolarGraph without the Rails integrations, run `gem install solargraph`.

The configuration file for SolarGraph itself can be found at `.solargraph.yml` within the root directory of Metasploit Framework.
For more information on how this works and how to tweak it, please refer to <https://solargraph.org/guides/configuration>.

Once the Gem files have been installed, the next step is to install the VSCode plugin. You can grab it from 
<https://marketplace.visualstudio.com/items?itemName=castwide.solargraph>. Once this is done, run the following commands
to ensure that SolarGraph is using the most up to date information about your code:

```
bundle install # Update all the gems
yard gems # Create documentation files for all the gems. SolarGraph relies on YARD for a lot of info.
yard doc -c # Create YARD docs for all files and use the cache so we don't repeat work (-c option).
solargraph bundle # Update Solargraph documentation for bundled gems
```

Then close down VSCode and restart it again, opening up the `metasploit-framework` directory again as a project if needs be.
This should result in the SolarGraph server starting and then taking a few minutes to index your files. Note that this
process may occur every time you open up the `metasploit-framework` project. This is normal and to be expected.

If you'd like to save yourself some time, you can have YARD automatically generate new documentation for installed Gems
by running `yard config --gem-install-yri` which will configure YARD to automatically generate documentation whenever
new Gems are installed.

# Debugging Metasploit

## Pry Debugging
Occasionally, simply reading through Metasploit code may not be helpful. You need to actually get into the weeds and learn
what a piece of code is doing. In these cases, it may be helpful to use `pry`, a Ruby Debugger that can be launched at
a specific place within your code and which allows you to view the state of the program at that time,
make adjustments as needed, and then either step through the program or continue to let it run.

You can enter into an interactive debugging environment using `pry` by adding the following code
snippet within your Metasploit module or library method:

```ruby
require 'pry'; binding.pry
```

Pry includes inbuilt commands for code navigation:

- `backtrace`: Show the current call stack
- `up` / `down`: Navigate the call stack
- `step`: Move forward by a single execution step
- `next`: Move forward by a single line
- `whereami`: Show the current breakpoint location again
- `help`: View all of the available commands and options

Ruby's runtime introspection can be used to view the available methods, classes, and variables within the current Ruby environment:

- `self`: To find out what the current object is
- `self.methods`: Find all available methods
- `self.methods.grep /send/`: Searching for a particular method that you're interested in. This can be great to explore unknown APIs.
- `self.method(:connect).source_location`: Find out which file, and which line, defined a particular method
- `self.class.ancestors`: For complex modules, this can be useful to see what mixins a Metasploit module is currently using

To learn more about Pry, we recommend reading GitLab's guide at <https://docs.gitlab.com/ee/development/pry_debugging.html>.

## Debug.gem Debugging
Ruby 3.1 and later come with `debug.gem` installed automatically, which is the new default debugger for Ruby. It replaces
the old `lib/debug.rb` library that was not actively being maintained and replaces it with a modern debugging library
capable of performing many debugging actions with next to no impact on the performance of the debugged application.

Whilst RubyMine does not support the `debug.gem` functionality, you can use VSCode to take advantage of `debug.gem`
to get speedy debugging of Ruby scripts from within VSCode itself. Simply install the debugging plugin
from <https://marketplace.visualstudio.com/items?itemName=KoichiSasada.vscode-rdbg>, then go to the Metasploit root directory,
and if you have Bundler installed, run `bundle install`. This will bring in the latest version of the `debug` gem.

Once this is all done, open the `metasploit-framework` folder from a cloned GitHub copy of Metasploit Framework in VSCode
by using `File->Open Folder`. Then click `Run->Add Configuration->Ruby(rdbg)`. This will create a file at
`<metasploit root>/.vscode/launch.json`. Replace the contents of this file with the contents of the file at
<https://github.com/rapid7/metasploit-framework/blob/master/external/vscode/launch.json>. If you wish, you can
optionally change the listening port from `55634` in the script to one of your choice.

Finally click `Run->Start Debugging` to start debugging Metasploit Framework using VSCode. This may cause a prompt to
appear that looks like `bundle exec ruby /home/tekwizz123/git/metasploit-framework/msfconsole`. Confirm this looks okay
and that you are using `bundle exec ruby` to execute `msfconsole`. If all looks good, hit the `ENTER` key to confirm.
At this point you should see Metasploit Framework open up.

If you want to prevent this prompt in the future then simply remove the `"askParameters": true,` line from `launch.json`.

Once in a debugging session, debug.gem supports the same commands as Pry in may cases, so the commands listed in the
Pry section above should work in the same manner. Additionally debug.gem also supports extra commands for things such as
tracing data. For more details refer to the command list at <https://github.com/ruby/debug#debug-command-on-the-debug-console>
which provides a detailed list of debug.gem's supported commands. For more information on the VSCode rdbg plugin,
refer to <https://code.visualstudio.com/docs/languages/ruby> and <https://marketplace.visualstudio.com/items?itemName=KoichiSasada.vscode-rdbg>.

## RubyMine Debugging
RubyMine comes with its own built in debugger that is based off of the old `lib/debug.rb` library in Ruby, however it
has custom patches and modifications applied to it by the JetBrains team. To set it up, first clone the Git repository
for Metasploit-Framework locally, then go `File->Open` and click on the `metasploit-framework` folder to open it as a project.

Once this is done, go to `Run->Edit Configurations` and click the plus sign to add a new configuration. Select
`Ruby`, and in the name field, enter a name that makes sense for you, such as `Metasploit Debug`. Under `Ruby Script`,
enter the full path to `msfconsole` on your local machine. Finally, set the SDK to either `Use Project SDK` or select
another Ruby SDK that RubyMine recognizes.

You can add a Ruby SDK by going to `File->Settings->Languages and Frameworks->Ruby SDK and Gems` and clicking the plus sign.