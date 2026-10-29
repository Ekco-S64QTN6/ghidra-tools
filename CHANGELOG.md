# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Fixed
- Make the headless launcher honor `GHIDRA_ROOT` and `JAVA_HOME`, use Ghidra's supported launcher for standard installs, and retain the Flatpak direct-JVM workaround with paths derived from the detected installation.
- Add mocked regression coverage for standard and Flatpak launcher selection and invalid Java configuration.
