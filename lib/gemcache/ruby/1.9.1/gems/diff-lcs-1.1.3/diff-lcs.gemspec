# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{diff-lcs}
  s.version = "1.1.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Austin Ziegler"]
  s.date = %q{2011-08-27}
  s.description = %q{Diff::LCS is a port of Perl's Algorithm::Diff that uses the McIlroy-Hunt
longest common subsequence (LCS) algorithm to compute intelligent differences
between two sequenced enumerable containers. The implementation is based on
Mario I. Wolczko's {Smalltalk version 1.2}[ftp://st.cs.uiuc.edu/pub/Smalltalk/MANCHESTER/manchester/4.0/diff.st]
(1993) and Ned Konz's Perl version
{Algorithm::Diff 1.15}[http://search.cpan.org/~nedkonz/Algorithm-Diff-1.15/].

This is release 1.1.3, fixing several small bugs found over the years. Version
1.1.0 added new features, including the ability to #patch and #unpatch changes
as well as a new contextual diff callback, Diff::LCS::ContextDiffCallbacks,
that should improve the context sensitivity of patching.

This library is called Diff::LCS because of an early version of Algorithm::Diff
which was restrictively licensed. This version has seen a minor license change:
instead of being under Ruby's license as an option, the third optional license
is the MIT license.}
  s.email = ["austin@rubyforge.org"]
  s.executables = ["htmldiff", "ldiff"]
  s.extra_rdoc_files = ["Manifest.txt", "docs/COPYING.txt", "History.rdoc", "License.rdoc", "README.rdoc"]
  s.files = ["History.rdoc", "License.rdoc", "Manifest.txt", "README.rdoc", "Rakefile", "bin/htmldiff", "bin/ldiff", "diff-lcs.gemspec", "docs/COPYING.txt", "docs/artistic.html", "lib/diff-lcs.rb", "lib/diff/lcs.rb", "lib/diff/lcs/array.rb", "lib/diff/lcs/block.rb", "lib/diff/lcs/callbacks.rb", "lib/diff/lcs/change.rb", "lib/diff/lcs/htmldiff.rb", "lib/diff/lcs/hunk.rb", "lib/diff/lcs/ldiff.rb", "lib/diff/lcs/string.rb", "spec/diff_spec.rb", "spec/lcs_spec.rb", "spec/patch_spec.rb", "spec/sdiff_spec.rb", "spec/spec_helper.rb", "spec/traverse_balanced_spec.rb", "spec/traverse_sequences_spec.rb", ".gemtest"]
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{ruwiki}
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{Diff::LCS is a port of Perl's Algorithm::Diff that uses the McIlroy-Hunt longest common subsequence (LCS) algorithm to compute intelligent differences between two sequenced enumerable containers}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rspec>, ["~> 2.0"])
      s.add_development_dependency(%q<hoe>, ["~> 2.10"])
    else
      s.add_dependency(%q<rspec>, ["~> 2.0"])
      s.add_dependency(%q<hoe>, ["~> 2.10"])
    end
  else
    s.add_dependency(%q<rspec>, ["~> 2.0"])
    s.add_dependency(%q<hoe>, ["~> 2.10"])
  end
end
