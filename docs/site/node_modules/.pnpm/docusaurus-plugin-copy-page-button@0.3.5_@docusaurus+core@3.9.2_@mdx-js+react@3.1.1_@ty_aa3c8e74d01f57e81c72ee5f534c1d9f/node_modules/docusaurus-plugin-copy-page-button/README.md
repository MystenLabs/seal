# Docusaurus Copy Page Button Plugin

[![npm version](https://badge.fury.io/js/docusaurus-plugin-copy-page-button.svg)](https://www.npmjs.com/package/docusaurus-plugin-copy-page-button)
[![npm downloads](https://img.shields.io/npm/dm/docusaurus-plugin-copy-page-button.svg)](https://www.npmjs.com/package/docusaurus-plugin-copy-page-button)

<img src="https://github.com/user-attachments/assets/2b91c2c9-97e7-4854-82dd-e1b6caa6511e" alt="Docusaurus Copy Page Button Plugin Preview" width="449" height="392" />

**Extract Docusaurus documentation content as markdown for AI tools like ChatGPT and Claude**

A lightweight Docusaurus plugin that automatically adds a "Copy page" button to your documentation site's sidebar. Perfect for developers who want to quickly extract documentation content for AI assistance, code reviews, or content analysis.

## Why Use This Plugin?

- **AI-Ready Content**: Instantly convert documentation pages to clean markdown for ChatGPT, Claude, or other AI tools
- **Developer Productivity**: Copy entire documentation pages without manual selection and cleanup
- **Zero Configuration**: Works out of the box - just install and go
- **Documentation Workflow**: Streamline the process of getting documentation context for AI assistance

## Features

- 📋 **Copy page as markdown** - Clean page content extraction
- 👁️ **View as markdown** - Preview extracted content in new tab
- 🤖 **AI integration** - Direct "Open in ChatGPT" and "Open in Claude" buttons
- ⚙️ **Configurable actions** - Show/hide specific dropdown actions (perfect for private sites)
- ⚡ **Auto-injection** - Automatically adds to table of contents sidebar (no configuration needed)
- 🎨 **Theme-aware** - Supports light/dark themes
- 🎨 **Customizable styling** - Easy custom CSS classes and inline styles
- 📱 **Mobile-friendly** - Responsive design
- 🛠️ **Zero-config** - Works out of the box with sensible defaults

## Installation

```bash
npm install docusaurus-plugin-copy-page-button
```

## Usage

### Option 1: Auto-injection (Recommended)

Add the plugin to your `docusaurus.config.js`:

```js
module.exports = {
  plugins: ["docusaurus-plugin-copy-page-button"],
};
```

The button will automatically appear in your table of contents sidebar!

### Option 2: Custom positioning

Use custom styles to position the button differently:

```js
module.exports = {
  plugins: [
    [
      "docusaurus-plugin-copy-page-button",
      {
        customStyles: {
          button: {
            style: {
              position: "fixed",
              top: "20px",
              right: "20px",
            },
          },
        },
      },
    ],
  ],
};
```

## Configuration

### Enabled Actions

You can control which actions appear in the dropdown menu using the `enabledActions` option. This is particularly useful for private documentation sites where the AI tool links (ChatGPT/Claude) won't work properly.

```js
module.exports = {
  plugins: [
    [
      "docusaurus-plugin-copy-page-button",
      {
        // Only show copy and view actions (hide ChatGPT and Claude)
        enabledActions: ['copy', 'view'],
      },
    ],
  ],
};
```

**Available actions:**
- `'copy'` - Copy page as Markdown
- `'view'` - View as Markdown in new tab
- `'chatgpt'` - Open in ChatGPT
- `'claude'` - Open in Claude

**Default:** All actions are enabled: `['copy', 'view', 'chatgpt', 'claude']`

**Example configurations:**

```js
// Only copy functionality
enabledActions: ['copy']

// Copy and view only (no AI tools)
enabledActions: ['copy', 'view']

// All actions including AI tools (default)
enabledActions: ['copy', 'view', 'chatgpt', 'claude']
```

### Custom Styling

You can customize the appearance of the copy page button by passing a `customStyles` option:

```js
module.exports = {
  plugins: [
    [
      "docusaurus-plugin-copy-page-button",
      {
        customStyles: {
          button: {
            className: "my-custom-button",
            style: {
              backgroundColor: "#4CAF50",
              color: "white",
              borderRadius: "8px",
            },
          },
          dropdown: {
            className: "my-custom-dropdown",
            style: {
              backgroundColor: "#f8f9fa",
              border: "2px solid #4CAF50",
            },
          },
          dropdownItem: {
            style: {
              padding: "12px 20px",
              fontSize: "16px",
            },
          },
          container: {
            className: "my-button-container",
          },
        },
      },
    ],
  ],
};
```

#### Available Style Targets

- **`button`** - The main copy page button (positioning styles like `position`, `top`, `left` are automatically applied to the container)
- **`dropdown`** - The dropdown menu that appears when clicking the button
- **`dropdownItem`** - Individual items in the dropdown menu
- **`container`** - The wrapper container around the button

#### Style Options

Each target accepts:
- **`className`** - CSS class name(s) to add to the element
- **`style`** - Inline styles object (React style format)

Custom styles are merged with the default styles, so you only need to specify what you want to change.

#### Example: Custom positioning

```js
module.exports = {
  plugins: [
    [
      "docusaurus-plugin-copy-page-button",
      {
        customStyles: {
          button: {
            style: {
              position: "fixed",
              top: "100px",
              left: "100px",
              zIndex: 1000,
            },
          },
        },
      },
    ],
  ],
};
```

**Note**: Positioning styles (`position`, `top`, `right`, `bottom`, `left`, `zIndex`, `transform`) specified in the `button` configuration are automatically applied to the container element for proper positioning control.

#### Example: Styling without positioning

```js
module.exports = {
  plugins: [
    [
      "docusaurus-plugin-copy-page-button",
      {
        customStyles: {
          button: {
            style: {
              backgroundColor: "transparent",
              border: "2px solid #007acc",
              color: "#007acc",
              borderRadius: "12px",
              fontWeight: "bold",
            },
          },
        },
      },
    ],
  ],
};
```

## Local Development

To test this plugin locally during development:

### 1. Clone and setup

```bash
git clone https://github.com/portdeveloper/docusaurus-plugin-copy-page-button.git
cd docusaurus-plugin-copy-page-button
npm install
```

### 2. Link the package

```bash
npm link
```

### 3. Use in your Docusaurus project

Navigate to your Docusaurus project and link the local plugin:

```bash
cd /path/to/your/docusaurus/project
npm link docusaurus-plugin-copy-page-button
```

### 4. Configure in docusaurus.config.js

Add the plugin to your config:

```js
module.exports = {
  plugins: ["docusaurus-plugin-copy-page-button"],
};
```

### 5. Start development server

```bash
npm start
```

The locally linked plugin will now be active in your Docusaurus site. Any changes you make to the plugin source will require restarting the Docusaurus development server.

## How It Works

The plugin intelligently extracts page content by:

1. **Smart Content Selection**: Automatically identifies the main documentation content area
2. **Clean Extraction**: Removes navigation, sidebars, headers, footers, and UI elements
3. **Markdown Conversion**: Converts HTML to properly formatted markdown with preserved structure
4. **AI-Optimized Format**: Includes page title, URL, and clean content perfect for AI tool input

## Use Cases

- **AI-Assisted Development**: Quickly share documentation context with ChatGPT or Claude for coding help
- **Code Reviews**: Extract relevant documentation for code review discussions
- **Content Analysis**: Analyze documentation structure and content for improvements
- **Knowledge Sharing**: Easily share specific documentation sections with team members
- **Documentation Migration**: Extract content for migrating to other documentation platforms

## SEO Keywords

Docusaurus plugin, copy page button, extract documentation, markdown conversion, AI tools integration, ChatGPT documentation, Claude AI, content extraction, developer tools, documentation productivity, React plugin, JavaScript documentation tools.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## Support

- 🐛 [Report Issues](https://github.com/portdeveloper/docusaurus-plugin-copy-page-button/issues)
- 💡 [Request Features](https://github.com/portdeveloper/docusaurus-plugin-copy-page-button/issues/new)
- 📖 [Documentation](https://github.com/portdeveloper/docusaurus-plugin-copy-page-button#readme)

## Reach out to me for faster replies!

My telegram username is portdev, feel free to dm me whenever (and bug me if I don't reply)

## License

MIT © [portdeveloper](https://github.com/portdeveloper)
