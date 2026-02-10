# docusaurus-plugin-plausible

<a href="https://www.npmjs.com/package/docusaurus-plugin-plausible"><img alt="npm docusaurus-plugin-plausible" src="https://img.shields.io/npm/v/docusaurus-plugin-plausible"/></a>

A Docusaurus plugin for [Plausible](https://plausible.io/) analytics. Inspired by [gatsby-plugin-plausible](https://github.com/Aquilio/gatsby-plugin-plausible).

---

- [Install](#install)
- [Options](#options)
- [License](#license)

## Install

1. Install `docusaurus-plugin-plausible`

  `npm install --save docusaurus-plugin-plausible`

2. Add plugin to `docusaurus.config.js`

  ```javascript
  module.exports = {
    ...
    plugins: [
      [
        'docusaurus-plugin-plausible',
        {
          domain: 'your-website.com',
        },
      ]
    ],
  };
  ```

### Options

 * `domain` (required) - The domain added in Plausible
 * `customDomain` - A custom domain if configured in Plausible
 * `excludePaths` - An array of paths to exclude when sending page view events

## License

[Apache License 2.0](https://choosealicense.com/licenses/apache-2.0/)
