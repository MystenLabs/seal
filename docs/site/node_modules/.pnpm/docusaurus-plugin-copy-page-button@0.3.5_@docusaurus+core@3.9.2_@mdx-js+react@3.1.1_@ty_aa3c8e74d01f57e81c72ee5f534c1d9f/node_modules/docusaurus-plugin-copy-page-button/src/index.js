const path = require("path");

module.exports = function copyPageButtonPlugin(context, options = {}) {
  const {
    customStyles = {},
    enabledActions = ['copy', 'view', 'chatgpt', 'claude'],
    ...otherOptions
  } = options;

  return {
    name: "copy-page-button-plugin",

    getClientModules() {
      return [path.resolve(__dirname, "./client.js")];
    },

    injectHtmlTags() {
      return {
        headTags: [
          {
            tagName: 'script',
            innerHTML: `
              window.__COPY_PAGE_BUTTON_OPTIONS__ = ${JSON.stringify({
                customStyles,
                enabledActions,
                ...otherOptions
              })};
            `
          }
        ]
      };
    },
  };
};
