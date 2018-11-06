## 1.3 / 2017-01-18

*   Bugs fixed:

    *   Fixed an error for bin/ldiff --version. Fixes [issue #21][].
    *   Force Diff::LCS::Change and Diff::LCS::ContextChange to only perform
        equality comparisons against themselves. Provided by Kevin Mook in
        [pull request #29][].
    *   Fix tab expansion in htmldiff, provided by Mark Friedgan in
        [pull request #25][].
    *   Silence Ruby 2.4 Fixnum deprecation warnings. Fixxues [issue #38][] and
        [pull request#36][].
    *   Ensure that test dependencies are loaded properly. Fixes [issue #33][]
        and [pull request #34][].
    *   Fix [issue #1][] with incorrect intuition of patch direction. Tentative
        fix, but the previous failure cases pass now.

*   Tooling changes:

    *   Added SimpleCov and Coveralls support.
    *   Change the homepage (temporarily) to the GitHub repo.
    *   Updated testing and gem infrastructure.
    *   Modernized the specs.

*   Cleaned up documentation.

*   Added a Code of Conduct.

## 1.2.5 / 2013-11-08

*   Bugs fixed:

    *   Comparing arrays flattened them too far, especially with
        Diff::LCS.sdiff. Fixed by Josh Bronson in [pull request #23][].

## 1.2.4 / 2013-04-20

*   Bugs fixed:

    *   A bug was introduced after 1.1.3 when pruning common sequences at the
        start of comparison. Paul Kunysch (@pck) fixed this in
        [pull request #18][]. Thanks!

    *   The Rubinius (1.9 mode) bug in [rubinius/rubinius#2268][] has been
        fixed by the Rubinius team two days after it was filed. Thanks for
        fixing this so quickly!

*   Switching to Raggi's hoe-gemspec2 for gemspec generation.

## 1.2.3 / 2013-04-11

*   Bugs Fixed:

    *   The new encoding detection for diff output generation (added in 1.2.2)
        introduced a bug if the left side of the comparison was the empty set.
        Originally found in [rspec/rspec-expectations#238][] and
        [rspec/rspec-expectations#239][]. Jon Rowe developed a reasonable
        heuristic (left side, right side, empty string literal) to avoid this
        bug.
    *   There is a known issue with Rubinius in 1.9 mode reported in
        [rubinius/rubinius#2268][] and demonstrated in the Travis CI builds.
        For all other tested platforms, diff-lcs is considered stable. As soon
        as a suitably small test-case can be created for the Rubinius team to
        examine, this will be added to the Rubinius issue around this.

## 1.2.2 / 2013-03-30

*   Bugs Fixed:

    *   Diff::LCS::Hunk could not properly generate a difference for comparison
        sets that are not US-ASCII-compatible because of the use of literal
        regular expressions and strings. Jon Rowe found this in
        [rspec/rspec-expectations#219][] and provided a first pass
        implementation in [pull request #15][]. I've reworked it because of
        test failures in Rubinius when running in Ruby 1.9 mode. This coerces
        the added values to the encoding of the old dataset (as determined by
        the first piece of the old dataset).
    *   Adding Travis CI testing for Ruby 2.0.

## 1.2.1 / 2013-02-09

*   Bugs Fixed:

    *   As seen in [rspec/rspec-expectations#200][], the release of
        Diff::LCS 1.2 introduced an unnecessary public API change to
        Diff::LCS::Hunk (see the change at
        [rspec/rspec-expectations@3d6fc82c][] for details). The new method name
        (and behaviour) is more correct, but I should not have renamed the
        function or should have at least provided an alias. This release
        restores Diff::LCS::Hunk#unshift as an alias to #merge. Note that the
        old #unshift behaviour was incorrect and will not be restored.

## 1.2.0 / 2013-01-21

*   Minor Enhancements:

    *   Added special case handling for Diff::LCS.patch so that it handles
        patches that are empty or contain no changes.
    *   Added two new methods (#patch\_me and #unpatch\_me) to the includable
        module.

*   Bugs Fixed:

    *   Fixed [issue #1][] patch direction detection.
    *   Resolved [issue #2][] by handling `string[string.size, 1]` properly (it
        returns `""` not `nil`).
    *   Michael Granger (ged) fixed an implementation error in
        Diff::LCS::Change and added specs in [pull request #8][]. Thanks!
    *   Made the code auto-testable.
    *   Vít Ondruch (voxik) provided the latest version of the GPL2 license
        file in [pull request #10][]. Thanks!
    *   Fixed a documentation issue with the includable versions of #patch! and
        #unpatch! where they implied that they would replace the original
        value. Given that Diff::LCS.patch always returns a copy, the
        documentation was incorrect and has been corrected. To provide the
        behaviour that was originally documented, two new methods were added to
        provide this behaviour. Found by scooter-dangle in [issue #12][].
        Thanks!

*   Code Style Changes:

    *   Removed trailing spaces.
    *   Calling class methods using `.` instead of `::`.
    *   Vít Ondruch (voxik) removed unnecessary shebangs in [pull request #9][].
        Thanks!
    *   Kenichi Kamiya (kachick) removed some warnings of an unused variable in
        lucky [pull request #13][]. Thanks!
    *   Embarked on a major refactoring to make the files a little more
        manageable and understand the code on a deeper level.
    *   Adding to http://travis-ci.org.

## 1.1.3 / 2011-08-27

*   Converted to 'hoe' for release.
*   Converted tests to RSpec 2.
*   Extracted the body of htmldiff into a class available from
    diff/lcs/htmldiff.
*   Migrated development and issue tracking to GitHub.
*   Bugs fixed:

    *   Eliminated the explicit use of RubyGems in both bin/htmldiff and
        bin/ldiff. Resolves [issue #4][].
    *   Eliminated Ruby warnings. Resolves [issue #3][].

## 1.1.2 / 2004-10-20

*   Fixed a problem reported by Mauricio Fernandez in htmldiff.

## 1.1.1 / 2004-09-25

*   Fixed bug #891 (Set returned from patch command does not contain last equal
    part).
*   Fixed a problem with callback initialisation code (it assumed that all
    callbacks passed as classes can be initialised; now, it rescues
    NoMethodError in the event of private :new being called).
*   Modified the non-initialisable callbacks to have a private #new method.
*   Moved ldiff core code to Diff::LCS::Ldiff (diff/lcs/ldiff.rb).

## 1.1.0 / -

*   Eliminated the need for Diff::LCS::Event and removed it.
*   Added a contextual diff callback, Diff::LCS::ContextDiffCallback.
*   Implemented patching/unpatching for standard Diff callback output formats
    with both #diff and #sdiff.
*   Extensive documentation changes.

## 1.0.4

*   Fixed a problem with bin/ldiff output, especially for unified format.
    Newlines that should have been present weren't.
*   Changed the .tar.gz installer to generate Windows batch files if ones do
    not exist already. Removed the existing batch files as they didn't work.

## 1.0.3

*   Fixed a problem with #traverse\_sequences where the first difference from
    the left sequence might not be appropriately captured.

## 1.0.2

*   Fixed an issue with ldiff not working because actions were changed from
    symbols to strings.

## 1.0.1

*   Minor modifications to the gemspec, the README.
*   Renamed the diff program to ldiff (as well as the companion batch file) so
    as to not collide with the standard diff program.
*   Fixed issues with RubyGems. Requires RubyGems > 0.6.1 or >= 0.6.1 with the
    latest CVS version.

## 1.0

*   Initial release based mostly on Perl's Algorithm::Diff.

[rubinius/rubinius#2268]: https://github.com/rubinius/rubinius/issues/2268
[rspec/rspec-expectations#239]: https://github.com/rspec/rspec-expectations/issues/239
[rspec/rspec-expectations#238]: https://github.com/rspec/rspec-expectations/issues/238
[rspec/rspec-expectations#219]: https://github.com/rspec/rspec-expectations/issues/219
[rspec/rspec-expectations@3d6fc82c]: https://github.com/rspec/rspec-expectations/commit/3d6fc82c
[rspec/rspec-expectations#200]: https://github.com/rspec/rspec-expectations/pull/200
[pull request #36]: https://github.com/halostatue/diff-lcs/pull/36
[pull request #34]: https://github.com/halostatue/diff-lcs/pull/34
[pull request #29]: https://github.com/halostatue/diff-lcs/pull/29
[pull request #25]: https://github.com/halostatue/diff-lcs/pull/25
[pull request #23]: https://github.com/halostatue/diff-lcs/pull/23
[pull request #18]: https://github.com/halostatue/diff-lcs/pull/18
[pull request #15]: https://github.com/halostatue/diff-lcs/pull/15
[pull request #13]: https://github.com/halostatue/diff-lcs/pull/13
[pull request #10]: https://github.com/halostatue/diff-lcs/pull/10
[pull request #9]: https://github.com/halostatue/diff-lcs/pull/9
[pull request #8]: https://github.com/halostatue/diff-lcs/pull/8
[issue #38]: https://github.com/halostatue/diff-lcs/issues/38
[issue #33]: https://github.com/halostatue/diff-lcs/issues/33
[issue #21]: https://github.com/halostatue/diff-lcs/issues/21
[issue #12]: https://github.com/halostatue/diff-lcs/issues/12
[issue #4]: https://github.com/halostatue/diff-lcs/issues/4
[issue #3]: https://github.com/halostatue/diff-lcs/issues/3
[issue #2]: https://github.com/halostatue/diff-lcs/issues/2
[issue #1]: https://github.com/halostatue/diff-lcs/issues/1
