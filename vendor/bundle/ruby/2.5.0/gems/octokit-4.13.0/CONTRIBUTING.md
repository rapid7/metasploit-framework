## Submitting a Pull Request

0. Check out Hacking on Octokit in the README guide for
   bootstrapping the project for local development.
1. [Fork the repository.][fork]
2. [Create a topic branch.][branch]
3. Add specs for your unimplemented feature or bug fix.
4. Run `script/test`. If your specs pass, return to step 3.
5. Implement your feature or bug fix.
6. Run `script/test`. If your specs fail, return to step 5.
7. Run `open coverage/index.html`. If your changes are not completely covered
   by your tests, return to step 4.
8. Add documentation for your feature or bug fix.
9. Run `bundle exec rake doc:yard`. If your changes are not 100% documented, go
   back to step 8.
10. Add, commit, and push your changes. For documentation-only fixes, please
    add "[ci skip]" to your commit message to avoid needless CI builds.
11. [Submit a pull request.][pr]

[fork]: https://help.github.com/articles/fork-a-repo
[branch]: https://help.github.com/articles/creating-and-deleting-branches-within-your-repository/
[pr]: https://help.github.com/articles/using-pull-requests
