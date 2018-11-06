## 3.0.1

 * Small doc updates

## 3.0.0

 * Fixes merging queries with CTE - chitux

## 2.4.1

 * Fixes error when creating a join between STI related models - edpaget

## 2.4.0

 * Fixes missing CTEProxy delegate - eidge
 * Fixes where chain on joins - edpaget
 * ActiveRecord 4.2 support added - edpaget

## 2.3.0

 * Fixes an issue with `where(table: { column: [] })` was not properly
   converting the where clause to an equality instead of an `IN`
   predicate (#111) - Dan McClain
 * Adds support for Rails 4.1 - Dan McClain
 * Adds support for hstore columns when using `contains` (#120) - Dan McClain
 * Quotes CTE names (#130) - Dan McClain

## 2.2.0

 * Adds Arel predications for `ANY` and `ALL` - Dan McClain
 * Fixes errors with has\_and\_belongs\_to\_many associations - Jacob Swanner
 * Adds with.recursive for recursive CTEs - Cody Cutrer
 * Relation.with now accepts Arel::SelectMangers - Dan McClain

## 2.1.3

 * Fixes Arel 4.0.1 issues - Dan McClain
 * Prevents coversion of string to order statement - Dan McClain

## 2.1.2

 * Fixes calls to count when ranking a relation - Dan McClain

## 2.1.1

 * Fixes cte proxy so that it can create records - Dan McClain

## 2.1.0

 * Support added for common table expressions - Dan McClain
 * Support added for rank windowing function - Dan McClain
 * Insert Code Climate badge into README - Doug Yun

# 2.0.0

 * JRuby fixes - Dan McClain
 * Updates docs and description - Dan McClain
 * Rails 4 support - Dan McClain

# 1.0.0

1.0.0 is the last major and minor release for Rails 3.2.x. Postgres\_ext
will only receive bug fixes in the future. Also, bug fixes for 1.0.x
will come from PRs only, future development efforts are concentrated on
2.x.

 * Fixing array tests in jruby - Dan McClain
 * Removes encoding patches from PostgreSQLAdapter - Dan McClain
 * Update documentation to reflect changes in 0.3.0 - Fabian Schwahn
 * Allow conversion of string/text columns to array - Valentino
 * Fix link to github issues in readme - Carlos Antonio da Silva

## 0.4.0
 * Adds support for (limited) support for PostgreSQL ranges - Dan McClain

## 0.3.1

 * Fixes issue with array -> string code - Dan McClain
 * Adds support for ISN types - Ezekiel Templin
 * Fix for Squeel compatibility - Alexander Borovsky

## 0.3.0

 * Adds support to create indexes concurrently  -  Dan McClain
 * Changes using syntax, updates specs  -  Dan McClain
 * Empty strings are converted to nil by string_to_cidr_address -  Dan McClain
 * Replaced .symbolize with .to_sym in arel nodes.  -  OMCnet Development Team
 * Removes array_contains in favor of a column aware contains  -  Dan McClain
 * Renames Arel array_overlap to overlap  -  Dan McClain
 * Merge pull request #67 from jagregory/array_contains Array contains operator support -  Dan McClain
 * Update querying doc to include array_contains  -  James Gregory
 * Array contains operator ( @> ) support -  James Gregory
 * how to use SQL to convert string-delimited arrays in docs -  Turadg Aleahmad
 * Check if connection responds to #support_extensions? before invoking it  -  Dirk von Grünigen

## 0.2.2

 * Fixes issue with visit_Array monkey patch - Dan McClain (@danmcclain)

## 0.2.1

 * Fixes issue with citext change column calls - Dan McClain
(@danmcclain)

## 0.2.0

 * Introduces extensions to `ActiveRecord::Relation.where` to simplify
Array and INET/CIDR queries - Dan McClain (@danmcclain)
 * Fixes `where(:array => [1,2])` to use equailty instead of IN clauses
- Dan McClain (@danmcclain)
 * Adds Arel predicates for more network comparisons - Patrick Muldoon
(@doon)
 * Adds support for citext in migrations/schema.rb - Jonathan Younger
(@daikini)
 * Fixes text character encoding for text columns - Andy Monat (@amonat)
 * Cleans up alias_method_chains for better interoperability - Raido
Paaslepp (@legendetm)
 * Doc updates - Dan McClain, Caleb Woods (@danmcclain @calebwoods)

## 0.1.0

 * Performs PostgreSQL version check before attempting to dumpe
extensions - Dan McClain (@danmcclain)
 * Fixes issues with schema dumper when indexes have no index_opclass -
Mario Visic (@mariovisic)

## 0.0.10

 * Fixes parsing of number arrays when they are set from a string array - Alexey Noskov (@alno)
 * Cleans up spec organization  - Dan McClain (@danmcclain)
 * Adds support for index operator classes (:index_opclass) in
migrations and schema dumps - & Dan McClain (@danmcclain)
 * Fixes Arel Nodes created by postgres_ext  - Dan McClain (@danmcclain)
 * Add support to schema.rb to export and import extensions - Keenan
Brock (@kbrock)
 * Handles PostgreSQL strings when passed in as defaults by fixing the
quote method
 * Documentation updates. - Dan McClain & Doug Yun (@danmcclain
@duggieawesome)
 * Fixes #update_column calls - Dan McClain (@danmcclain)


## 0.0.9

 * Fixes #<attribute_name>?, Adds (pending) test case for #update_column - Dan McClain (@danmcclain)
 * Fix handing of pgsql arrays for the literal and argument-binding
cases - Michael Graff (@skandragon)
 * Fixes UTF-8 strings in string arrays are not returned as UTF-8
encoded strings - Michael Graff (@skandragon)
 * Documentation fixes - Michael Graff (@skandragon) and Dan McClain
(@danmcclain)
 * Properly encode strings stored in an array. - Michael Graff
(@skandragon)
 * Fixes integer array support - Keenan Brock (@kbrock)
 * Adds more robust index types with add_index options :index_type and :where. - Keenan Brock (@kbrock)

## 0.0.8

Fixes add and change column

## 0.0.7

Adds Arel predicate functions for array overlap operator (`&&`) and
INET/CIDR contained within operator (`<<`)

## 0.0.6

Lots of array related fixes:
 * Model creation should no longer fail when not assigning a value to an
   array column
 * Array columns follow database defaults

Migration fix (rn0 and gilltots)
Typos in README (bcardarella)
