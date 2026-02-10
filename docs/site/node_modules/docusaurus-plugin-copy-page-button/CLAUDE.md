# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Docusaurus plugin that adds a "Copy page" button to documentation sites, allowing users to extract page content as markdown for use with LLMs and AI tools.

## Key Architecture

### Core Components

- **src/index.js** - Main plugin entry point that registers the plugin with Docusaurus and passes options to the client-side code
- **src/CopyPageButton.js** - React component that renders the copy button and dropdown with actions (copy, view, open in AI tools)
- **src/client.js** - Client-side injection logic that automatically adds the button to the Docusaurus sidebar
- **src/styles.module.css** - CSS styles for the copy button and dropdown

### Plugin Architecture

This is a client-side Docusaurus plugin that:
1. Registers itself via the main plugin function in `src/index.js`
2. Uses `getClientModules()` to inject client-side code
3. Uses `injectHtmlTags()` to pass configuration options to the browser
4. Auto-injects the copy button into the table of contents sidebar

### Client-Side Injection Strategy

The plugin uses a sophisticated injection system in `src/client.js`:
- **Fast injection** for SPA navigation when sidebar already exists
- **Reliable injection** for page refreshes with retry logic and timeout handling
- **Responsive handling** for layout changes and mobile/desktop transitions
- **Route change detection** using multiple strategies (popstate, docusaurus events, URL monitoring)

### Content Extraction

The `CopyPageButton.js` component includes comprehensive markdown conversion logic that:
- Extracts main content from Docusaurus article containers
- Removes navigation, UI elements, and buttons
- Converts HTML to clean markdown with proper formatting
- Handles code blocks, tables, lists, and admonitions
- Cleans up various text encoding issues

## Development Workflow

Since this is a pure Docusaurus plugin with no build step:
- No npm scripts for building, testing, or linting
- Changes to source files are immediately usable
- Test by linking the package locally and using in a Docusaurus project

### Local Testing Process
1. `npm link` in this repository
2. `npm link docusaurus-plugin-copy-page-button` in target Docusaurus project
3. Add plugin to `docusaurus.config.js`
4. Start Docusaurus development server to test changes

## Configuration Options

The plugin accepts a `customStyles` option for styling the button, dropdown, and container elements. Positioning styles from button config are automatically moved to the container for proper layout control.

## Browser Environment Requirements

- Only runs in browser environment (uses `ExecutionEnvironment.canUseDOM`)
- Requires React 18+ and Docusaurus 3.0+ (specified in peerDependencies)
- Uses modern browser APIs like clipboard and DOM manipulation