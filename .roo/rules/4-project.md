# Lightbridge Authz

- configs are in the [config](../../config) folder.
- configs are done via yaml files
- to start the app, a single config is required.
- We'll axum (latest version) as server
- Error handling is centralized in the core module. If a Result, better use that one. If not yet supported, propose me
  to add the error case to the enum.
- Never keep all logic in a single file. Files shouldn't be too long. The same way, check other files to see if
  something you want to do wasn't implemented already.
- Always write comment to document the code directly.
