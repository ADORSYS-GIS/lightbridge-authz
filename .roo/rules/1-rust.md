# Rust Development Rules for AI Assistant

1. Edition and Version Management

- Use Rust edition 2024 exclusively
- Maintain existing dependency versions; only propose upgrades after verifying latest stable versions online
- Never suggest downgrading any crate versions
- Always verify version compatibility through official sources before suggesting changes
- Don't include comments in your code.

2. Workspace Dependency Management

- All dependencies must be declared in the workspace-level Cargo.toml
- Individual crates should reference workspace dependencies using `workspace = true`
- If a dependency exists in a crate but not in workspace, add it to workspace Cargo.toml with the appropriate version
- Better expose a dependency from a module, than importing the same dep on all modules.
- Example:
  In workspace Cargo.toml
  ```toml
  [workspace.dependencies]
  serde = { version = "1.0", features = ["derive"] }
  ```

  In crate Cargo.toml
  ```toml
  [dependencies]
  serde.workspace = true
  ```

3. Dependency Research

- Check memory or research all dependencies using "https://docs.rs/<package_name>/<package_version>" before
  implementation
- Understand crate functionality, API stability, and usage patterns
- Verify that proposed dependencies are actively maintained and have reasonable download counts
- Save knowledge into memory for future use

4. Testing Requirements

- Create dedicated test files in the `tests/` directory for all new features
- Move any existing tests from `src/` directory to `tests/` folder
- Update existing tests when modifying features
- Ensure test coverage for both success and failure cases
- Use appropriate test attributes like `#[should_panic]` when applicable

5. Documentation Standards

- Write comprehensive documentation for all public APIs
- Include examples in documentation comments using `///` and `//!`
- Document struct fields, enum variants, and function parameters
- Add module-level documentation explaining component purpose and usage

6. Stability Requirements

- Do not use nightly Rust features
- Stick to stable Rust toolchain only
- Avoid experimental or unstable standard library features
- Ensure all code compiles with stable rustc

7. Code Quality Guidelines

- Follow Rust naming conventions (snake_case for variables/functions, PascalCase for types)
- Use rustfmt for code formatting
- Apply clippy suggestions for improved code quality
- Prefer idiomatic Rust patterns over direct translations from other languages

8. Error Handling

   - Use the custom Result<T> in [error.rs](../../crates/lightbridge-authz-core/src/error.rs) and upgrade Error on new errors
   - Use Result<T> for operations that can fail
   - Implement proper error propagation with ? operator
   - Create custom error types when appropriate
   - Handle all possible error cases explicitly

9. Performance Considerations

   - Prefer owned data structures when ownership is needed
   - Use references (&T) as much as possible to avoid unnecessary cloning
   - Consider using Cow<str> for optimization when dealing with string data
   - Leverage iterator chains for efficient data processing

10. Safety Rules
    - Avoid unsafe code unless absolutely necessary
    - When using unsafe, provide detailed comments explaining why it's needed
    - Ensure memory safety in all unsafe blocks
    - Validate all assumptions in unsafe code paths