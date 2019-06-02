# Bundled Modules

Created by Adam Cammack

As Metasploit modules continue to grow in number and capability the current separation of module information by type grows more cumbersome. Starting next year, we want all the files related to a module (docs, libraries, sources, build info, etc.) to live as closely together and be as hackable as possible. To this end, we have come up with the concept of "module bundles" to help improve module dependency isolation and locality of information. We hope the format will prove flexible enough to accommodate the wide range of modules we have and uniform enough to not cause confusion among community members and contributors. Eventually, we may even be able to package each module separately for distribution.

Whether or not this bundled format will support the old style of module is uncertain. It could be made to work, I think, but it would require a fair bit of effort and ingenuity to work cleanly. For simplicity, I will describe the bundle concept as it applies to external/coldstone modules and then describe potential adaptations at the end.

## Directory structure

Example complicated Ruby module:

```
$ tree --dirsfirst --charset=ascii -F bundled_module/
bundled_module/
|-- data/
|   `-- stack_smash
|-- docs/
|   |-- bundled_module.md
|   |-- poc.py
|   `-- success.pcap
|-- lib/
|   |-- foo/
|   |   |-- bar.rb
|   |   `-- baz.rb
|   `-- foo.rb
|-- src/
|   `-- stack_smash.s
|-- templates/
|   `-- exploit.ps.erb
|-- Dockerfile
|-- Gemfile
|-- Gemfile.lock
|-- Rakefile
|-- bundled_module.rb*
`-- metadata.json
```

## Aside: things I'm not sure of and reference vaguely

 - Would the main executable be named after the module (same as the directory, maybe with extension), or given a 
 - standard name?
 - Would the JSON metadata file be named after the module or given a standard name?
 - Would we ever allow multiple closely related modules per directory? (eg. routersploit integration, impacts how we think about the above)
 - If so or not, how would we deal with closely related functionality that has different options for different actions?
 - Do things like client blobs (HTML, JavaScript, images, etc.) belong in data/ or should we also have a static/? (static/ seems to get a bit fiddly to me; data/static/?)

## Required files

To keep overhead to a minimum for hackers who are developing modules, we need to minimize files that the author will need to create, touch, and understand for most tasks (restated: every file an author must touch should be directly related to particular and specialized functionality that they want as part of the preparation or execution of a module). The most minimal module only requires the main executable to be present. When loading modules, framework will see a leaf directory without certain expected files and will generate the default ones automatically. This behaviour can be later augmented with guessing of which defaults based on what _is_ present in the directory.

 - If Rakefile is absent, framework will generate one that references the shared rake tasks.
 - If Gemfile is absent and the executable ends in .rb, framework will generate one that depends on the bridge libraries from source.
 - If metadata.json is absent, framework will generate it using rake.

All this generation logic should be available as part of a standalone scaffolding tool.

## Keeping it all close

One of the drawbacks of the current module system is that all the files related to the development, documentation, and execution of a module live in different places. Some information, like dependencies, is only tracked implicitly or lossily in code or in the top-level specifications of framework. This makes programmatically determining what a module is, targets, or requires fraught with fragile code.

### Metadata

The metadata will be kept in JSON in a file (or several, see my uncertainties above) that is built by rake. Keeping the metadata cached per-module gives us several capabilities. First, updates look more logical in commits, and the files can be updated as part of the standard PR/landing process. Next, dependency tracking of when the metadata needs to be updated can be offloaded to standard build tool capabilities.

Because invoking rake has overhead, any metadata that exists should be considered correct during initial module discovery. Any modules without metadata should then have it generated via rake. Next, every module should have its metadata building task run to (and stale metadata replaced) ensure correctness. If a module is use'd before this process completes, it must have it metadata refreshed via rake if needed as part of the loading process. Since modules are independent, the whole discovery/refreshing process is parallelizable, reducing wall time.

In addition to the information we currently cache, we will want to cache any information a user might see or want to know so that, if the cached metadata is more recent than any module files, nothing has to be built or run to use the module. Notably, this includes options and module archetype (which in the future directly map options for user convince, vs the shim approach take today).

### Build info

All additional build info should be specified as tasks in the module Rakefile. As much a possible, this should also include building with IDE environments, like Visual Studio. Even if the binaries are checked in to reduce runtime requirements (see below), it is still invaluable to know how something was built in the first place.

### Blobs and sources

Sources are handy, it should be easy to find them! Now they will live in the module in the src/ directory. Here the Rakefile can easily find them and transform them into the beautiful exploitation resources they were meant to be.

As much as possible, only sources should be checked into the tree. For super-specific platform targeting things though, that's not always feasible (eg. VisualStudio projects). It's times like these that the {{data/}} directory should be used. As mentioned above, the Rakefile should still be able to build the thing given the correct environment.

Blobs or assets without a checked-in source also belong in data/, like images or downloaded things. Things for client exploits to download should probably also go in here, like HTML files and static JavaScripts.

### Templates

Modules that use a large literal interspersed with runtime data should use the templates/ directory to store templates. ERB should be used for printable data by Ruby, and equivalents for other languages (DTL, mustache, etc.). Binary data should maybe be blobs with accompanying offset listings?

### Docs

The docs/ directory will contain the files that a user will reference when trying to understand module. This may include PoCs, markdown, pcaps, etc. The HTML we currently show to users would be generated from the module and files here using rake tasks.

### Additional tooling

One advantage that this directory structure gives us is the ability to write better tooling for it than we have for the current iteration of modules. One downside is that we will need it to in order to make the format accessible to hackers.

### Shared build tasks

Because all routine module-oriented tasks will be preformed with rake tasks, we will need to make the default actions for these tasks as intelligent and reusable as possible across different module types/implementations. A module author should not have to worry about writing plumbing they do not need (or is common) or messing with plumbing that is only tangentially related to their unique need. To that end, we should have sane defaults for the following at a minimum:

```
rake run -- Start module, hook up stdin/stdout to JSON-RPC
rake metadata -- Generate metadata JSON
rake tidy:code -- Run tidiness checks against the code
rake tidy:metadata -- Run tidiness checks against the metadata
rake doc:text -- Combine all docs into a plain-text, human readable thing
rake doc:html -- Similar to today's info -d
rake deps -- Install dependencies local to the current user, if possible
rake deps:check -- Check to see if a module can likely be run in the current environment
rake build -- Build files that need it, defaults: src/FILE.s => data/FILE (extracted from exe format), ...?
rake clean -- Remove generated files
rake clobber -- Reset to pristine, checked-out state
```

### Module generation

At the very least, we will also need tooling to create a mostly-empty but runnable module so that an author knows what to poke when writing. This skeleton can be augmented by questions that can help us use different archetypes, like payload vs. remote, or Ruby vs. Python. These commands could also point the author to relevant module writing articles/documentation.

### For classic modules

The biggest differences for classic modules are metadata generation and running. These can be accomplished with rake tasks, but it would involve starting up a whole framework instance for each module run. For efficiency, we will need to signal to framework to treat the module specially, perhaps having rake deps:check output/return a specific value when the module needs to be run inside of framework. Metadata would then be dumped directly from the framework loader, and instead of rake run, the classic module loader/runner would be run much as it is today. We will probably want to keep the rake tasks for these things for when we don't already have a framework instance handy.