# Contributing to This Project

Thanks for considering making a contribution to Seal or its documentation. Before you get started, please take a moment to read these guidelines.

## Important Note

We appreciate contributions, but **simple typo fixes (e.g., minor spelling errors, punctuation changes, or trivial rewording) will be ignored** unless they significantly improve clarity or fix a critical issue. If you are unsure whether your change is substantial enough, consider opening an issue first to discuss it.

## Example Frontend Application

The example frontend in this repository is provided as a reference implementation only. We will not accept pull requests for UI/UX improvements or cosmetic changes to the example frontend unless they fix actual bugs or critical issues. The example is meant to demonstrate functionality, not serve as a production-ready application.

We encourage you to use this example as a starting point for your own frontend applications. If you build upon this example to create your own implementation, we'd love to hear about it! Feel free to share your projects with the community, and we may highlight notable implementations in our documentation or community channels.

## Reporting Issues

Found a bug or security vulnerability? Please check the existing issues before opening a new one.

Provide as much detail as possible, including steps to reproduce the issue, expected behavior, and actual behavior.

## Documentation

Is something missing or incorrect in our documentation? You can make a PR if you prefer to fix it yourself.

For larger documentation issues, please create an issue in GitHub.

## Proposing Code Changes

Fork the repository and create a new branch for your changes. Ensure your branch is based on the latest `main`.

Follow the coding style and conventions used in the project, see [*Code Standards*](#code-standards) and [*Pre-commit Hooks*](#pre-commit-hooks) for further details.

If your change is significant, please open an issue first to discuss it.

## Submitting a Pull Request

Ensure your changes are well-tested. Provide a clear description of your changes in the pull request.

Reference any relevant issue numbers in your pull request. Be responsive to feedback from maintainers.

## Code Standards

Follow existing code structure and formatting.

Write meaningful commit messages.

Ensure all tests pass before submitting a pull request.

## Pre-commit Hooks

We have CI jobs running for every PR to test and lint the repository. You can install Git pre-commit
hooks to ensure that these check pass even *before pushing your changes* to GitHub. To use this, the
following steps are required:

1. Install [Rust](https://www.rust-lang.org/tools/install).
1. Install [nextest](https://nexte.st/).
1. [Install pre-commit](https://pre-commit.com/#install) using `pip` or your OS's package manager.
1. Run `pre-commit install -c .pre-commit-config-example.yaml` in the repository.

After this setup, the code will be checked, reformatted, and tested whenever you create a Git commit.

You can also use adjust the pre-commit configuration or use a different pre-commit configuration if you wish:

1. Create a file `.pre-commit-config.yaml`, optionally copying and adapting `.pre-commit-config-example.yaml`
   (this is set to be ignored by Git).
1. Run `pre-commit install -c .pre-commit-config.yaml`.

## License

By contributing, you agree that your contributions will be licensed under the same license as this project.

Thank you for contributing!
