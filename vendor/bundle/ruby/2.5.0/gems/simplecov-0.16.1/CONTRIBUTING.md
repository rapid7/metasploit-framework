## Reporting Issues

You can report issues at https://github.com/colszowka/simplecov/issues

Before you go ahead please search existing issues for your problem, chances are someone else already reported it.

To make sure that we can help you quickly please include and check the following information:

 * Include how you run your tests and which testing framework or frameworks you are running.
    - please ensure you are requiring and starting SimpleCov before requiring any application code.
    - If running via rake, please ensure you are requiring SimpleCov at the top of your Rakefile
      For example, if running via RSpec, this would be at the top of your spec_helper.
    - Have you tried using a [`.simplecov` file](https://github.com/colszowka/simplecov#using-simplecov-for-centralized-config)?
 * Include the SimpleCov version you are running in your report.
 * If you are not running the latest version (please check), and you cannot update it,
   please specify in your report why you can't update to the latest version.
 * Include your `ruby -e "puts RUBY_DESCRIPTION"`.
 * Please also specify the gem versions of Rails (if applicable).
 * Include any other coverage gems you may be using and their versions.

Include as much sample code as you can to help us reproduce the issue. (Inline, repo link, or gist, are fine. A failing test would help the most.)

This is extremely important for narrowing down the cause of your problem.

Thanks!

## Making Contributions

To fetch & test the library for development, do:

    $ git clone https://github.com/colszowka/simplecov.git
    $ cd simplecov
    $ bundle
    $ bundle exec rake

If you want to contribute, please:

  * Fork the project.
  * Make your feature addition or bug fix.
  * Add tests for it. This is important so I don't break it in a future version unintentionally.
  * **Bonus Points** go out to anyone who also updates `CHANGELOG.md` :)
  * Send me a pull request on GitHub.

## Running Individual Tests

This project uses RSpec and Cucumber. Individual tests can be run like this:

```bash
bundle exec rspec path/to/test.rb
bundle exec cucumber path/to/test.feature
```
