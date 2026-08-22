# Ghost Starter Theme

A starter framework for Ghost themes! Click **Use this template** to create a copy of this repo for everything you need to get started developing a custom Ghost theme.

&nbsp;

## First time using a Ghost theme?

Ghost uses a simple templating language called [Handlebars](http://handlebarsjs.com/) for its themes.

We've documented this starter theme pretty heavily so that it should be possible to work out what's going on just by reading the code and the comments. We also have a robust set of resources to help you build awesome custom themes:

- The official [theme documentation](https://ghost.org/docs/themes) is the complete resource for everything you need to know about Ghost theme development
- [Tutorials](https://ghost.org/tutorials/) offer a step-by-step guide to building the most common features in Ghost themes
- The [Ghost VS Code extension](https://marketplace.visualstudio.com/items?itemName=TryGhost.ghost) speeds up theme development and provides quick access to helpful info
- All of Ghost's official themes are [open source](https://github.com/tryghost) and are a great reference for learning how to create a theme

&nbsp;

## Starter theme features

🔁&nbsp;Livereload by default. See changes instantly in the browser whenever you save a file.

🔎&nbsp;Optimized for VS Code. Find the files you're looking for more easily.

🗃️&nbsp;Write modern JavaScript. Use ESM out of the box to write more manageable Javascript.

🗜️&nbsp;Assets optimized automatically. JavaScript and CSS are minified and transpiled by default.

👟&nbsp;Fast compile times, powered by [Rollup](https://rollupjs.org).

🦋&nbsp;Write next-gen CSS for today's browsers with [PostCSS](https://postcss.org/). Add the CSS tools you love via [`rollup.config.js`](rollup.config.js).

🚢&nbsp;Ghost's [GH Deploy Action](.github/workflows/deploy-theme.yml) included by default. [Learn more how to deploy your theme automatically](https://github.com/TryGhost/action-deploy-theme)

➕&nbsp;Extensible by design. Rollup's configuration structure makes it easy to add [any number of plugins easily](https://github.com/rollup/plugins). 

&nbsp;

## Theme structure

The main files are:

- [`default.hbs`](default.hbs) - The main template file
- [`index.hbs`](index.hbs) - Used for the home page
- [`post.hbs`](post.hbs) - Used for individual posts
- [`page.hbs`](page.hbs) - Used for individual pages
- [`tag.hbs`](tag.hbs) - Used for tag archives
- [`author.hbs`](author.hbs) - Used for author archives

One neat trick is that you can also create custom one-off templates just by adding the slug of a page to a template file. For example:

- `page-about.hbs` - Custom template for the `/about/` page
- `tag-news.hbs` - Custom template for `/tag/news/` archive
- `author-jamie.hbs` - Custom template for `/author/jamie/` archive

&nbsp;

## Development guide

The Starter theme provides a first-class development experience out of the box. 

&nbsp;

### Setup

To see realtime changes during development, symlink the Starter theme folder to the `content/themes` folder in your local Ghost install. 

```bash
ln -s /path/to/starter /ghost/content/themes/starter
```

Restart Ghost and select the Starter theme from **Settings**.

From the theme's root directory, install the dependencies:

```bash
npm install
```

If Node isn't installed, follow the [official Node installation guide](https://nodejs.org/).

&nbsp;

### Start development mode

From the Starter theme folder, start development mode:

```bash
npm run dev
```

Changes you make to your styles, scripts, and Handlebars files will show up automatically in the browser. CSS and Javascript will be compiled and output to the `built` folder.

Press `ctrl + c` in the terminal to exit development mode.

&nbsp;

### Build, zip, and test your theme

Compile your CSS and JavaScript assets for production with the following command:

```bash
npm run build
```

Create a zip archive:

```bash
npm run zip
```

Use `gscan` to test your theme for compatibility with Ghost:

```bash
npm run test
```

&nbsp;



## Copyright & License

Copyright (c) 2013-2026 Ghost Foundation - Released under the [MIT license](LICENSE).
