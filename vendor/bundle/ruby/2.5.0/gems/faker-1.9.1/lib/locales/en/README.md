To keep the English locale file from getting unwieldy, this directory is
used for the translations that you might expect to find in `en.yml` in
the parent directory.  Each file in this directory corresponds to the
Faker class of the same name.  That is, `internet.yml` in this directory
contains the data for the methods in `Faker::Internet`.

Use the following YAML as the beginning of any new file you add to this
directory:

```
en:
  faker:
```
