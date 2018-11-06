# Contribute

Want to show Sinatra some love? Help out by contributing!

## Found a bug?

Log it in our [issue tracker][ghi] or send a note to the [mailing list][ml].
Be sure to include all relevant information, like the versions of Sinatra and
Ruby you're using. A [gist](http://gist.github.com/) of the code that caused
the issue as well as any error messages are also very helpful.

## Need help?

The [Sinatra mailing list][ml] has over 900 subscribers, many of which are happy
to help out newbies or talk about potential feature additions. You can also
drop by the [#sinatra](irc://chat.freenode.net/#sinatra) channel on
[irc.freenode.net](http://freenode.net).

## Have a patch?

Bugs and feature requests that include patches are much more likely to
get attention. Here are some guidelines that will help ensure your patch
can be applied as quickly as possible:

1. **Use [Git](http://git-scm.com) and [GitHub](http://github.com):**
   The easiest way to get setup is to fork the
   [sinatra/sinatra repo](http://github.com/sinatra/sinatra/).
   Or, the [sinatra.github.com repo](http://github.com/sinatra/sinatra.github.com/),
   if the patch is doc related.

2. **Write unit tests:** If you add or modify functionality, it must
   include unit tests. If you don't write tests, we have to, and this
   can hold up acceptance of the patch.

3. **Mind the `README`:** If the patch adds or modifies a major feature,
   modify the `README.md` file to reflect that. Again, if you don't
   update the `README`, we have to, and this holds up acceptance.

4. **Update the change log (`CHANGELOG.md`):** The change log helps give an
   overview of the changes that go into each release, and gives credit
   where credit is due. We make sure that the change log is up to date
   before each release, and we always appreciate it when people make
   it easier to get the release out the door.

5. **Push it:** Once you're ready, push your changes to a topic branch
   and add a note to the ticket with the URL to your branch. Or, say
   something like, "you can find the patch on johndoe/foobranch". We also
   gladly accept GitHub [pull requests](http://help.github.com/pull-requests/).

__NOTE:__ _We will take whatever we can get._ If you prefer to attach diffs in
emails to the mailing list, that's fine; but do know that _someone_ will need
to take the diff through the process described above and this can hold things
up considerably.

## Want to write docs?

The process for contributing to Sinatra's website, documentation or the book
is the same as contributing code. We use Git for versions control and GitHub to
track patch requests.

* [The sinatra.github.com repo](http://github.com/sinatra/sinatra.github.com/)
  is where the website sources are managed. There are almost always people in
  `#sinatra` that are happy to discuss, apply, and publish website patches.

* [The Book](http://sinatra-book.gittr.com/) has its own [Git
  repository](http://github.com/sinatra/sinatra-book/) and build process but is
  managed the same as the website and project codebase.

* [Sinatra Recipes](http://recipes.sinatrarb.com/) is a community
  project where anyone is free to contribute ideas, recipes and tutorials. Which
  also has its own [Git repository](http://github.com/sinatra/sinatra-recipes).

* [The Introduction](http://www.sinatrarb.com/intro.html) is generated from
  Sinatra's [README file](http://github.com/sinatra/sinatra/blob/master/README.md).

* If you want to help translating the documentation, the README is already
  available in
  [Japanese](http://github.com/sinatra/sinatra/blob/master/README.ja.md),
  [German](http://github.com/sinatra/sinatra/blob/master/README.de.md),
  [Chinese](https://github.com/sinatra/sinatra/blob/master/README.zh.md),
  [Russian](https://github.com/sinatra/sinatra/blob/master/README.ru.md),
  [European](https://github.com/sinatra/sinatra/blob/master/README.pt-pt.md) and
  [Brazilian](https://github.com/sinatra/sinatra/blob/master/README.pt-br.md)
  Portuguese,
  [French](https://github.com/sinatra/sinatra/blob/master/README.fr.md),
  [Spanish](https://github.com/sinatra/sinatra/blob/master/README.es.md),
  [Korean](https://github.com/sinatra/sinatra/blob/master/README.ko.md), and
  [Hungarian](https://github.com/sinatra/sinatra/blob/master/README.hu.md).
  The translations tend to fall behind the English version. Translations into
  other languages would also be appreciated.

## Looking for something to do?

If you'd like to help out but aren't sure how, pick something that looks
interesting from the [issues][ghi] list and hack on. Make sure to leave a
comment on the ticket noting that you're investigating (a simple "Taking…" is
fine).

[ghi]: http://github.com/sinatra/sinatra/issues
[ml]: http://groups.google.com/group/sinatrarb/topics "Sinatra Mailing List"
