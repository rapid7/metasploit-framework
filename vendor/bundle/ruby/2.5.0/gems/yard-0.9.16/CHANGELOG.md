# master

# [0.9.16] - August 11th, 2018

[0.9.16]: https://github.com/lsegal/yard/compare/v0.9.15...v0.9.16

- Documentation fixes (#1175, #1178).
- Fixed stack overflow issue when parsing extremely large lists (#1176).

# [0.9.15] - July 17th, 2018

[0.9.15]: https://github.com/lsegal/yard/compare/v0.9.14...v0.9.15

- Fixed security issue in parsing of Ruby code that could allow for arbitrary
  execution. Credit to Nelson Elhage <nelhage@nelhage.com> for discovering this
  issue.

# [0.9.14] - June 2nd, 2018

[0.9.14]: https://github.com/lsegal/yard/compare/v0.9.13...v0.9.14

- Fixed a regression in symbol parsing (#1170).

# [0.9.13] - May 28th, 2018

[0.9.13]: https://github.com/lsegal/yard/compare/v0.9.12...v0.9.13

- Added support for grouped constants via `@!group` directive (#1056).
- Added support for quoted symbols (#1168).
- Added support for i18n in tag text (#1169).
- Fixed HTML rendering of inline code blocks (#1152).
- Fixed rendering of anchor URLs in rendered HTML (#1154).

# [0.9.12] - November 26th, 2017

[0.9.12]: https://github.com/lsegal/yard/compare/v0.9.11...v0.9.12

- Be more explicit about lack of support for absolute paths in extra files
  specified by `yard doc` command.

# [0.9.11] - November 23rd, 2017

[0.9.11]: https://github.com/lsegal/yard/compare/v0.9.10...v0.9.11

- Fixed security issue in `--readme` that allowed for arbitrary file reads on
  disk. Credit to ztz <ztz@ztz.me> for discovering this issue.
- Improved styling for inline code blocks (#1142).

# [0.9.10] - November 18th, 2017

[0.9.10]: https://github.com/lsegal/yard/compare/v0.9.9...v0.9.10

- Added `--fail-on-warning` option for `yard doc` which exits with a non-zero
  code if there are any warnings (#1093).
- Added support for parsing inside `Struct.new` blocks (#1099).
- Added support new ripper AST tokens (#1104, #1124).
- Fixed an issue where `@see (obj)` reference tags would fail (#1111)
- Fix sorting in `yard stats` (#1123).

# [0.9.9] - April 23rd, 2017

[0.9.9]: https://github.com/lsegal/yard/compare/v0.9.8...v0.9.9

- Added `gem uninstall` hooks to remove YARD documentation files. (#1083)
- Added support for C++ namespaces. (#809)
- Fixed issue where loading a .html page via an anchor would not scroll to
  the anchor section. (#1082)
- Hide some Ruby warnings.
- Improve progress indicator icons in terminal.

# [0.9.8] - January 13th, 2017

[0.9.8]: https://github.com/lsegal/yard/compare/v0.9.7...v0.9.8

- Fixed installed gems not being correctly found in `yard server` and by plugins.
- Fixed tokenization of `%w(...)` array syntax.

# [0.9.7] - January 9th, 2017

[0.9.7]: https://github.com/lsegal/yard/compare/v0.9.6...v0.9.7

- Fixed resolution of absolute object paths with ambiguous names. (#1029)

# [0.9.6] - January 7th, 2017

[0.9.6]: https://github.com/lsegal/yard/compare/v0.9.5...v0.9.6

- Removed official support for Ruby 1.x (1.8/1.9). YARD can still be installed
  in these versions, but support is not guaranteed. Simple bug fixes may still
  be considered via pull request only. Issues without code will be automatically
  closed.
- Added {YARD::Tags::Tag#explain_types} returning a plain English summary
  of the type specification of a given tag. Also adds {YARD::Tags::TypesExplainer}
  as an implementation class for the method.
- Added support for automatic linking of constants and method calls of
  Ruby syntax highlighted source code in generated HTML. Also adds the
  {YARD::Parser::Ruby::TokenResolver} implementation class to iterate over
  tokenized code with extra resolved object information.
- Added support for compound constant assignments (`A::B::C = true`).
- Added `LibraryVersion#yardoc_file_for_SOURCE` callback method for sources with
  a pre-determined yardoc file location. Implement this method instead of
  manually setting `library.yardoc_file = ...` in your load method (you can
  still assign the attribute manually).
- Use RubyGems 2.x+ API to query gems when available instead of using backport.
- Various bug fixes

# [0.9.5] - July 22nd, 2016

[0.9.5]: https://github.com/lsegal/yard/compare/v0.9.4...v0.9.5

- `yard doc` will now generate `.yardoc/processing` and `.yardoc/complete` files
  to allow other tools to properly detect when YARD is in the middle of parsing
  source files, and when it has completed writing the database.
- Added support for on-demand generation of LibraryVersion objects using the
  `:disk` source type. LibraryVersion objects pointing to a .yardoc database
  directory will now auto-generate if there is a `source_path` attached.
- Added warning for macros attached to non-method objects.
- Fixed a few more parsing errors.

# [0.9.4] - July 21st, 2016

[0.9.4]: https://github.com/lsegal/yard/compare/v0.9.3...v0.9.4

- Minor Ruby file parsing and CSS bug fixes.

# [0.9.3] - July 20th, 2016

[0.9.3]: https://github.com/lsegal/yard/compare/v0.9.2...v0.9.3

- Added support for {YARD::Server::RackAdapter} to be mounted under prefix URIs.
- Fixed regression in `yard server -g` that caused static file assets on index
  page to return 404 errors.
- Fixed regression in `yard server -g` index page that disabled scrolling and
  caused other HTML rendering glitches.

# [0.9.2] - July 19th, 2016

[0.9.2]: https://github.com/lsegal/yard/compare/v0.9.1...v0.9.2

- Added `yard config --gem-install-[yri|yard]` commands which auto-configure
  your `~/.gemrc` file to run yri/yard instead of ri/rdoc on a `gem install`.
- Added support for gemspec metadata key `"yard.run"`, which can be either
  `"yard"` or `"yri"` to run the respective commands on a `gem install`.
- Added `yard doc --no-progress` to hide the progress bar.
- Fix resolution error for compound proxy namespaces.
- YRI will now search across all gem versions (latest first) for the .yardoc
  database.

# [0.9.1] - July 18th, 2016

[0.9.1]: https://github.com/lsegal/yard/compare/v0.9.0...v0.9.1

- Added "Attributes" section to `yard stats`.
- Added support for RubyGems 2.x `--document=yri,yard` flags. You can now run
  YARD documentation generation against installed gems by running:
  `gem install mygem --document=yard,yri`.
- Added `/static/*` routing for library-specific routing. This enables static
  template files to be served on a per-library basis instead of globally shared
  across the `yard server`.
- Added support for inlining of `{include:*}` syntax. Using this syntax in
  the middle of a docstring paragraph will no longer create a separate paragraph
  for the included text.
- Added support for resolving `{}` syntax in text templates, specifically for
  use in `{include:*}` syntax.
- Improved object resolution logic in `{Foo::Bar}` syntax and {YARD::Registry.resolve}.
  New resolution logic should now more accurately support resolving compound paths
  across namespaces and through the inheritance tree (as Ruby does).
- The `frozen_string_literal: true` comment line in Ruby source files will now be
  excluded from docstrings.
- Added a workaround for https://bugs.ruby-lang.org/issues/11485
- Fixed an issue where type using a docstring reference on an `@!attribute` macro
  would be incorrectly parsed as a type specifier. This change updates the tag
  parser to disallow newlines between the tag name and opening bracket of the
  type specification.
- Fixed an issue where `--embed-mixins` would improperly embed methods from
  inherited classes instead of modules.
- Fixed various parsing errors and YARD exceptions.
- Added a warning for modules or classes being redefined as constants.
- Reverted stripping of HTML in {YARD::Docstring#summary}.
- Added optimization to remove initial docstring parse on newly created code objects.
- {YARD::CodeObjects::Base#format} now passes the :type parameter to templates.
- Hide methods with filtered namespaces in Method Listing.

# [0.9.0] - July 4th, 2016

[0.9.0]: https://github.com/lsegal/yard/compare/v0.8.7.6...v0.9.0

Special thanks to Alex Dowad, MSP-Greg, and Alex McLain for their extended
contributions to this version.

- (Breaking Change): Replaced default template with an updated "frameless" version.
  This change may affect backward compatibility if custom templates made modifications
  to `default/fulldoc/html`, specifically the index or navigation lists.
- Added support for Ruby 2.1+ decorator style method declaration syntax. YARD now
  supports:
    private def foo(x, y) end
- Metadata headers in extra files can now be escaped from rendering by enclosing them
  in HTML comment blocks (`<!--\n @metadata here... \n-->`). Ensure that the opening
  comment tag is alone on the first line of the file to use this functionality.
- Improved parsing of various CRuby coding styles.
- Fixed issue with binary image assets when using `yard server`.
- Fixed deprecation warnings from Rake 10.x.
- Tests updated for RSpec 3.

# [0.8.7.6] - October 26, 2014

[0.8.7.6]: https://github.com/lsegal/yard/compare/v0.8.7.5...v0.8.7.6

- Support using `@option` tag on keyword arg splat parameter. (#729)
- Add `.stats_options` for `YardocTask`. (#800, #801)

# [0.8.7.5] - October 26, 2014

[0.8.7.5]: https://github.com/lsegal/yard/compare/v0.8.7.4...v0.8.7.5

- Fix linking of methods in top level namespace in method listing. (#776)
- Support using C macros in function declarations. (#810)
- YARD will no longer group comment blocks starting on the same column if they
  are preceded by code. (#798)
- Handle anonymous lambda calls in toplevel scope. (#774)
- Support I18n in `@overload` tags. (#794)
- Support `yard stats` for objects with no file property. (#792)
- Support for named arguments in Ruby >= 2.1. (#785)
- Exclude README backup files from YARD generation. (#790)
- Turned on the lax spacing option in Redcarpet to comply with the
  Markdown standard.
- Escape HTML in YARD server search placeholder template.
- Fix issue with `private_class_method` support. (#760, #767)
- Enable tables support by default in Redcarpet Markdown provider. (#765)

# 0.8.7.4 - March 22, 2014

[0.8.7.4]: https://github.com/lsegal/yard/compare/v0.8.7.3...v0.8.7.4

- Mark C methods as explicit but also remove explicit check in stats. (#727)
- Report unresolved parent namespaces as undocumentable errors instead. (#753)
- No longer ignore overridden methods from documentation check in stats (#719)
- Fix JRuby throwing exception when remove_method called on non-existent method. (#732)
- Add basic support for `private_class_method` (#747)
- Ensure namespace is always set when parent module is not found. (#753)
- Set overflow as auto on table of contents.
- Report 100% documented if nothing is undocumented. (#754)
- Added support for RubyGems 2.0.0+. (#742)
- Allow users to enter their own YARD RakeTask name. (#705)
- Fixed a typo that was causing Windows detection to always fail. (#715)
- Add debug information when loading a plugin fails. (#711)

# [0.8.7.3] - November 1, 2013

[0.8.7.3]: https://github.com/lsegal/yard/compare/v0.8.7.2...v0.8.7.3

- Handle Unicode method/class/file names in server URL encoding (lsegal/rubydoc.info#69).
- Style keyword style hashes with same symbol color in code highlighting (#707).
- Fix broken JS when visiting docs in file:// scheme (#706).
- Add support for new AsciiDoc file extensions (#704).
- Fix issues where non-Ruby code blocks would not display in Ruby 2 (#702).
- Add support for extra Ruby 2 symbol types in Ripper (#701).
- Ensure config directory exists before saving config file (#700).

# [0.8.7.2] - September 18, 2013

[0.8.7.2]: https://github.com/lsegal/yard/compare/v0.8.7.1...v0.8.7.2

- Disallow absolute URLs when using frame anchor support.
- Support casted functions in CRuby method declarations (#697)

# [0.8.7.1] - September 11, 2013

[0.8.7.1]: https://github.com/lsegal/yard/compare/v0.8.7...v0.8.7.1

- Fix potential XSS issue with frame anchor support.
- Add support for gettext 3.x gem.

# [0.8.7] - July 26, 2013

[0.8.7]: https://github.com/lsegal/yard/compare/v0.8.6.2...v0.8.7

- Added `--hide-api API` option to hide objects with a given `@api` tag (#685).
- Added "Returns ...." prefix to summary when a lone @return tag is used.
- Fixed issue that caused ref tags to be added to a docstring twice (#678).
- Fixed formatting issue in docstring summaries (#686)

# [0.8.6.2] - June 27, 2013

[0.8.6.2]: https://github.com/lsegal/yard/compare/v0.8.6.1...v0.8.6.2

- Fixed issue where `yard graph` was not displaying methods

# [0.8.6.1] - April 14, 2013

[0.8.6.1]: https://github.com/lsegal/yard/compare/v0.8.6...v0.8.6.1

- Fixed broken links in File menu on default HTML template
- Added --layout switch to `yard display` to wrap output in layout template.
- See {file:docs/WhatsNew.md} for more information on added features.

# [0.8.6] - April 13, 2013

[0.8.6]: https://github.com/lsegal/yard/compare/v0.8.5.2...v0.8.6

- Various fixes and improved Ruby 2.x compatibility support
- Added support for `asciidoc` markup type
- Added `yard markups` command to list available markup types
- Added `yard display` command to display and format an individual object
- See {file:docs/WhatsNew.md} for more information on added features.

# [0.8.5.2] - February 26, 2013

[0.8.5.2]: https://github.com/lsegal/yard/compare/v0.8.5.1...v0.8.5.2

- Support new keyword argument syntax in method signatures (Ruby 2.x)

# [0.8.5.1] - February 25, 2013

[0.8.5.1]: https://github.com/lsegal/yard/compare/v0.8.5...v0.8.5.1

- Fix `yard diff` of gem files with RubyGems 2.x

# [0.8.5] - February 24, 2013

[0.8.5]: https://github.com/lsegal/yard/compare/v0.8.4.1...v0.8.5

- Basic support for Ruby 2.0 (fix compat issues in RDoc 4.0, RubyGems 2.0)
- Add CSS styling for tables in default HTML template

# [0.8.4.1] - February 5, 2013

[0.8.4.1]: https://github.com/lsegal/yard/compare/v0.8.4...v0.8.4.1

- Fix regression that broke loading of existing yardoc dbs (#648)

# [0.8.4] - February 4, 2013

[0.8.4]: https://github.com/lsegal/yard/compare/v0.8.3...v0.8.4

- Add `-B/--bind` switch to yard server (#593, #608)
- Add CodeObjects::Base#title for plugins to customize how object
  links display (#646)
- Disable linking objects filtered out by verifiers (#645)
- Allow macro expansion on class methods (#632)
- Expand newly attached macro on first DSL method call (#631)
- Disable RubyGems plugin in Ruby 2.0 (#627)
- Fix line range for class/module node bodies (#626)
- Search extended modules for attached DSL macros (#553)

# [0.8.3] - October 14, 2012

[0.8.3]: https://github.com/lsegal/yard/compare/v0.8.2.1...v0.8.3

- Add `--non-transitive-tag` to disable tag transitivity (#571)
- Support --db inside .yardopts for graph/server commands (#583, #586)
- Fix handling for =begin/=end docstrings (#577, #578)
- Parser only sorts file lists when a glob is provided (#572)
- Fix formatting in `{include:Object#method}` syntax (#569)
- Fix @option tag inside of module functions (#563)
- Fix to `--api` and `--no-api` support (#559)
- Fix class nesting issues when path starts with "::" (#552)

# [0.8.2.1] - June 9, 2012

[0.8.2.1]: https://github.com/lsegal/yard/compare/v0.8.2...v0.8.2.1

- Fix a set of regressions in yard server search and dynamic generation

# [0.8.2] - June 7, 2012

[0.8.2]: https://github.com/lsegal/yard/compare/v0.8.1...v0.8.2

- Added progress style output in tty terminals
- Embedded mixins should ignore methods defined on module (#539)
- Fixed permalinks for embedded mixins in `yard server` (#540)
- Improve parsing in CRuby code (#543)
- Ensure Registry.resolve picks module when parsing mixins (#545)
- Fixed regression that caused various commands to not show output (#548)
- Respect current visibility when parsing class conditions (#551)

# [0.8.1] - May 2, 2012

[0.8.1]: https://github.com/lsegal/yard/compare/v0.8.0...v0.8.1

- Added `--[no-]api` switch to generate docs for API sets (see {file:docs/WhatsNew.md} for details) (#532)
- The `yard list` command now uses cache by default (#533)
- Fix `yardoc` generating incorrectly named method list file (#528)
- Fix HTML output occasionally showing trailing mdash on options list (#522)

# [0.8.0] - April 30, 2012

[0.8.0]: https://github.com/lsegal/yard/compare/v0.7.5...v0.8.0

- See {file:docs/WhatsNew.md} for a list of added features
- Over 20 bug fixes:
  - Properly filter hidden setter/getter attributes (#394)
  - Fix test failures in Linux environments (#397, #472, #473, #512, #513)
  - Fix attribute inheritance and @private (#432)
  - Fix attribute parsing (#435)
  - Allow aliases for attributes (#436)
  - Fix namespace fetching in `handle_alias()` (#437)
  - Fix overwritten attributes marked as inherited (#442)
  - Fix documenting constants defined from C code with `rb_define_const()` (#443)
  - Do not escape snippets twice (#445)
  - Ajax method/class search should not fire when a non-printable character is pressed (#446)
  - Fix yard server crashing when RDoc is not installed (#456)
  - Fix tags ignored when `(see #foo)` is used (#457)
  - Fix three "Returns" for two `@overload` tags (#458)
  - Do not auto-detect DSL methods as method objects if parameter name is not a valid method name (#464)
  - Fix attaching of macros to Object (#465)
  - Fix handling of `%w()` source in `[]/[]=` parsed context. (#461, pull in #468)
  - Don't add default `@return` if `@overload` has `@return`. (#458, pull in #469)
  - Don't discard tags by (see ...). (#457, pull in #470)
  - Fix constants listed as inherited when overwritten (#474)
  - Fix `yardoc --asset` behaving differently on first and subsequent calls. (#477)
  - `!!!lang` code blocks should set the lang in `<pre>`'s class. (#478, #479)
  - Fix "File List" search tab error. (#502)
  - Fix search bar not redirecting to method page. (#509)
  - Fix server returning exception message bodies as String (#518)

# [0.7.5] - January 31, 2012

[0.7.5]: https://github.com/lsegal/yard/compare/v0.7.4...v0.7.5

- Various minor bug fixes

# [0.7.4] - December 2, 2011

[0.7.4]: https://github.com/lsegal/yard/compare/v0.7.3...v0.7.4

- Redcarpet is now the default Markdown formatting library. GFM now works out-of-box (#404)
- Fix server side searching for elements that are marked private (#420)
- Add 'textile_strict' and 'pre' markup types, reorganize text and none (#416)
- Improve encoding line detection (#415)
- Add support for `rb_define_alias` in CRuby code (#413)
- Fix rendering of some keywords in source view (#410)
- Add support for RDoc 3.10+ (#406, #407)
- Fix typewriter text being processed in code blocks (#403)
- Improve support for has_rdoc in RubyGems 1.8.x (#401)
- See the {file:docs/WhatsNew.md} document for details on added features

# [0.7.3] - October 15, 2011

[0.7.3]: https://github.com/lsegal/yard/compare/v0.7.2...v0.7.3

- Improve support for parsing under Ruby 1.9.2p290 and 1.9.3 (#365, #370)
- Add support for SWIG generated CRuby code (#369)
- Add support for `rb_define_attr` calls in CRuby code (#362)
- Handle file pointers in CRuby code (#358)

# [0.7.2] - June 14, 2011

[0.7.2]: https://github.com/lsegal/yard/compare/v0.7.1...v0.7.2

- Fix `yard --help` not showing proper output
- YARD now expands path to `.yardoc` file in daemon mode for server (#328)
- Fix `@overload` tag linking to wrong method (#330)
- Fix incorrect return type when using `@macro` (#334)
- YARD now requires 'thread' to support RubyGems 1.7+ (#338)
- Fix bug in constant documentation when using `%w()` (#348)
- Fix YARD style URL links when using autolinking markdown (#353)

# [0.7.1] - May 18, 2011

[0.7.1]: https://github.com/lsegal/yard/compare/v0.7.0...v0.7.1

- Fixes a bug in `yard server` not displaying class list properly.

# [0.7.0] - May 17, 2011

[0.7.0]: https://github.com/lsegal/yard/compare/v0.6.8...v0.7.0

- See the {file:docs/WhatsNew.md} document for details on added features
- Make sure that Docstring#line_range is filled when possible (#243)
- Set #verifier in YardocTask (#282)
- Parse BOM in UTF-8 files (#288)
- Fix instance attributes not showing up in method list (#302)
- Fix rendering of %w() literals in constants (#306)
- Ignore keyboard shortcuts when an input is active (#312)
- And more...

# [0.6.8] - April 14, 2011

[0.6.8]: https://github.com/lsegal/yard/compare/v0.6.7...v0.6.8

- Fix regression in RDoc 1.x markup loading
- Fix regression in loading of markup libraries for `yard server`

# [0.6.7] - April 6, 2011

[0.6.7]: https://github.com/lsegal/yard/compare/v0.6.6...v0.6.7

- Fix has_rdoc gem specification issue with new RubyGems plugin API (oops!)

# [0.6.6] - April 6, 2011

[0.6.6]: https://github.com/lsegal/yard/compare/v0.6.5...v0.6.6

- Fix error message when RDoc is not present (#270)
- Add markup type 'none' to perform basic HTML translation (fallback when RDoc is not present)
- Add support for RubyGems 1.7.x (#272)
- Fix rendering of `{url description}` syntax when description contains newline

# [0.6.5] - March 13, 2011

[0.6.5]: https://github.com/lsegal/yard/compare/v0.6.4...v0.6.5

- Support `ripper` gem in Ruby 1.8.7
- Upgrade jQuery to 1.5.1
- Fix handling of alias statements with quoted symbols (#262)
- Add CSS styles (#260)
- Unhandled exception in YARD::Handlers::Ruby::MixinHandler indexing documentation for eventmachine (#248)
- Splice any alias references on method re-definitions into separate methods (#247)
- Fix "yard graph" (#245)
- Don't process ++ typewriter text inside of HTML attributes (#244)
- Prioritize loading of Kramdown before Maruku (#241)
- Skip shebang encoding in docstrings (#238)
- Fix truncation of references in @deprecated (#232)
- Show @api private note when no other tags are present (#231)
- Detect docstrings starting with "##" as `Docstring#hash_flag` (#230)
- Remove trailing whitespace from freeform tags (#229)
- Fix line through for deprecated methods (#225)
- Mistake in Tags.md (#223)
- Improve database storage by being more efficient with filesystem usage (#222)
- Make Registry thread local (#221)
- Support `private_constant` class method for 1.9.3 (#219)
- Do not assume RDoc is installed (#214)

# [0.6.4] - December 21, 2010

[0.6.4]: https://github.com/lsegal/yard/compare/v0.6.3...v0.6.4

- Fix yri tool crashing with new Config class (gh-217)
- Fix support for ::TopLevelConstants (gh-216)
- YARD's test suite is now RSpec2 compatible (gh-215)
- Improved documentation for YARD::Server features (gh-207)
- Fix displaying of collaped method summary lists (gh-204)
- Fix automatic loading of markup providers (gh-206)
- Fix keyboard shortcuts for Chrome (gh-203)
- Disallow `extend self` inside of a class (gh-202)
- Constants now recognized in C extensions (gh-201)

# [0.6.3] - November 21, 2010

[0.6.3]: https://github.com/lsegal/yard/compare/v0.6.2...v0.6.3

- Fixed regression that caused `yardoc --markup` to silently exit

# [0.6.2] - November 15, 2010

[0.6.2]: https://github.com/lsegal/yard/compare/v0.6.1...v0.6.2

- **Plugins no longer automatically load, use `--plugin` to load a plugin**
- Added YARD::Config and ~/.yard/config YAML configuration file
- Added `yard config` command to view/edit YARD configuration file
- Fixes for YARD in 1.8.6 (gh-178)
- Various HTML template adjustments and fixes (gh-198,199,200)
- Improved `yard server -m` multi-project stability (gh-193)
- Fixed handling of `yardoc --no-private` with missing class definitions (gh-197)
- Added support for constants defined in C extensions (gh-177)
- Added support for Structs defined as "Klass = Struct.new(...)" (gh-187)
- Improved parsing support for third-party gems (gh-174,180)
- Improved support for JRuby 1.6.4+. YARD now passes all specs in JRuby (gh-185)
- Improved YARD documentation (gh-172,191,196)

# [0.6.1] - September 06, 2010

[0.6.1]: https://github.com/lsegal/yard/compare/v0.6.0...v0.6.1

- Fixed TOC showing on top of class/method list in no-frames view
- A message now displays when running `yard server` with Rack/Mongrel installed
- Improved performance of JS inline search for large class/method lists
- Improved link titles for relative object links
- Removed `String#camelcase` and `String#underscore` for better Rails compat.
- Fixed support for loading .yardoc files under Windows
- Fixed inheritance tree arrows not displaying in certain environments

# [0.6.0] - August 29, 2010

[0.6.0]: https://github.com/lsegal/yard/compare/v0.5.8...v0.6.0

- Added dynamic local documentation server
- Added @group/@endgroup declarations to organize methods into groups
- Added `yard` executable to serve as main CLI tool with pluggable commands
- Added `--asset` switch to `yardoc` to copy files/dirs to output dir
- Added ability to register/manipulate tags via CLI (`--tag`, etc.)
- Added `yard diff` command
- Added statistics to `yardoc` output (and `yard stats` command)
- Added Javascript generated Table of Contents to file pages
- Updated various APIs
- Removed `yard-graph` executable
- See more changes in the {file:docs/WhatsNew.md what's new document}

# [0.5.8] - June 22, 2010

[0.5.8]: https://github.com/lsegal/yard/compare/v0.5.7...v0.5.8

- Merge fix from 0.6 branch for --no-private visibility checking

# [0.5.7] - June 21, 2010

[0.5.7]: https://github.com/lsegal/yard/compare/v0.5.6...v0.5.7

- Fixed visibility flag parsing in `yardoc`
- Updated Parser Architecture documentation with new SourceParser API
- Improved Registry documentation for new load commands
- Fix loading of .yardoc file as cache (and preserving aliases)
- Fix "lib" directory missing when running YARD on installed gems

# [0.5.6] - June 12, 2010

[0.5.6]: https://github.com/lsegal/yard/compare/v0.5.5...v0.5.6

- Bug fixes for RubyGems plugin, `has_rdoc=false` should now work
- New API for registering custom parsers. See {file:docs/WhatsNew.md}

# [0.5.5] - May 22, 2010

[0.5.5]: https://github.com/lsegal/yard/compare/v0.5.4...v0.5.5

- Various bug fixes

# [0.5.4] - March 22, 2010

[0.5.4]: https://github.com/lsegal/yard/compare/v0.5.3...v0.5.4

- See {file:docs/WhatsNew.md what's new document} for changes

# [0.5.3] - January 11, 2010

[0.5.3]: https://github.com/lsegal/yard/compare/v0.5.2...v0.5.3

- See {file:docs/WhatsNew.md what's new document} for changes

# [0.5.2] - December 16, 2009

[0.5.2]: https://github.com/lsegal/yard/compare/v0.5.1...v0.5.2

- See {file:docs/WhatsNew.md what's new document} for changes

# [0.5.1] - December 15, 2009

[0.5.1]: https://github.com/lsegal/yard/compare/v0.5.0...v0.5.1

- See {file:docs/WhatsNew.md what's new document} for changes

# [0.5.0] - December 13, 2009

[0.5.0]: https://github.com/lsegal/yard/compare/v0.4.0...v0.5.0

- See {file:docs/WhatsNew.md what's new document} for changes

# [0.4.0] - November 15, 2009

[0.4.0]: https://github.com/lsegal/yard/compare/v0.2.3.5...v0.4.0

- Added new templating engine based on [tadpole](http://github.com/lsegal/tadpole)
- Added YARD queries (`--query` CLI argument to yardoc)
- Greatly expanded YARD documentation
- Added plugin support
- New `@abstract` and `@private` tags
- Changed default rake task to `rake yard`
- Read about changes in {file:docs/WhatsNew.md}

# [0.2.3.5] - August 13, 2009

[0.2.3.5]: https://github.com/lsegal/yard/compare/v0.2.3.4...v0.2.3.5

- Minor bug fixes.

# [0.2.3.4] - August 07, 2009

[0.2.3.4]: https://github.com/lsegal/yard/compare/v0.2.3.3...v0.2.3.4

- Minor bug fixes.

# [0.2.3.3] - July 26, 2009

[0.2.3.3]: https://github.com/lsegal/yard/compare/v0.2.3.2...v0.2.3.3

- Minor bug fixes.

# [0.2.3.2] - July 06, 2009

[0.2.3.2]: https://github.com/lsegal/yard/compare/v0.2.3.1...v0.2.3.2

- Fix Textile hard-break issues
- Add description for @see tag to use as link title in HTML docs.
- Add --title CLI option to specify a title for HTML doc files.
- Add custom.css file that can be overridden with various custom
  styelsheet declarations. To use this, simply add `default/fulldoc/html/custom.css`
  inside your code directory and use the `-t` template directory yardoc CLI
  option to point to that template directory (the dir holding 'default').
- Add support in `yardoc` CLI to specify extra files (formerly --files)
  by appending "- extra files here" after regular source files. Example:

        yardoc --private lib/**/*.rb - FAQ LICENSE

# [0.2.3.1] - June 13, 2009

[0.2.3.1]: https://github.com/lsegal/yard/compare/v0.2.3...v0.2.3.1

- Add a RubyGems 1.3.2+ plugin to generate YARD documentation instead of
  RDoc. To take advantage of this plugin, set `has_rdoc = 'yard'` in your
  .gemspec file.

# [0.2.3] - June 07, 2009

[0.2.3]: https://github.com/lsegal/yard/compare/v0.2.2...v0.2.3

- See the {file:docs/WhatsNew.md} file for a list of important new features.

# [0.2.2] - Jun 16, 2008

[0.2.2]: https://github.com/lsegal/yard/compare/v0.2.1...v0.2.2

- This is the largest changset since yard's conception and involves a complete
  overhaul of the parser and API to make it more robust and far easier to
  extend and use for the developer.

# [0.2.1] - February 20, 2008

[0.2.1]: https://github.com/lsegal/yard/compare/v0.1a...v0.2.1

- See the {file:docs/WhatsNew.md} file for a list of important new features.

# 0.1a - February 24, 2007

- Released 0.1a experimental version for testing. The goal here is
  to get people testing YARD on their code because there are too many possible
  code styles to fit into a sane amount of test cases. It also demonstrates the
  power of YARD and what to expect from the syntax (Yardoc style meta tags).
