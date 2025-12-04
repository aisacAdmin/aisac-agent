# Contributing to AISAC Agent

Thank you for your interest in contributing to AISAC Agent! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Security](#security)

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive environment for all contributors.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Make
- Git
- golangci-lint (for linting)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/aisac-agent.git
   cd aisac-agent
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/cisec/aisac-agent.git
   ```

## Development Setup

1. Install dependencies:
   ```bash
   go mod download
   ```

2. Build the project:
   ```bash
   make build
   ```

3. Run tests:
   ```bash
   make test
   ```

4. Run linter:
   ```bash
   make lint
   ```

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-action-name` - New features
- `fix/issue-description` - Bug fixes
- `docs/update-readme` - Documentation changes
- `refactor/component-name` - Code refactoring

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(actions): add collect_forensics action

fix(agent): handle reconnection timeout correctly

docs(readme): update installation instructions
```

## Code Style

### Go Code

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Use `gofmt` for formatting
- Use `golangci-lint` for linting
- Keep functions focused and small
- Add comments for exported functions and types

### File Organization

```
internal/
├── actions/         # Action implementations
│   ├── action_name.go
│   └── action_name_test.go
├── agent/           # Agent logic
├── config/          # Configuration
├── callback/        # SOAR callbacks
└── platform/        # Platform-specific code
    ├── *_linux.go
    ├── *_windows.go
    └── *_darwin.go
```

### Adding a New Action

1. Create `internal/actions/new_action.go`:
   ```go
   package actions

   type NewAction struct {
       logger zerolog.Logger
   }

   func NewNewAction(logger zerolog.Logger) *NewAction {
       return &NewAction{
           logger: logger.With().Str("action", "new_action").Logger(),
       }
   }

   func (a *NewAction) Name() types.ActionType {
       return types.ActionNewAction
   }

   func (a *NewAction) Validate(params map[string]interface{}) error {
       // Parameter validation
       return nil
   }

   func (a *NewAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
       // Implementation
       return types.ActionResult{Success: true}, nil
   }
   ```

2. Add action type to `pkg/types/types.go`
3. Register in `internal/actions/executor.go`
4. Add tests in `internal/actions/new_action_test.go`
5. Update documentation

### Platform-Specific Code

Use build tags for platform-specific implementations:

```go
//go:build linux

package platform

// Linux-specific implementation
```

## Testing

### Running Tests

```bash
# All tests
make test

# With coverage
make test-coverage

# Specific package
go test -v ./internal/actions/...

# Specific test
go test -v ./internal/actions -run TestBlockIP
```

### Writing Tests

- Use table-driven tests
- Test edge cases and error conditions
- Mock external dependencies
- Aim for >80% coverage on new code

Example:
```go
func TestNewAction_Validate(t *testing.T) {
    logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
    action := NewNewAction(logger)

    tests := []struct {
        name    string
        params  map[string]interface{}
        wantErr bool
    }{
        {
            name:    "valid params",
            params:  map[string]interface{}{"key": "value"},
            wantErr: false,
        },
        {
            name:    "missing required param",
            params:  map[string]interface{}{},
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := action.Validate(tt.params)
            if (err != nil) != tt.wantErr {
                t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

## Submitting Changes

### Pull Request Process

1. Update your branch with latest upstream:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. Run all checks:
   ```bash
   make lint
   make test
   make build
   ```

3. Push your branch:
   ```bash
   git push origin feature/your-feature
   ```

4. Create a Pull Request on GitHub

### PR Requirements

- [ ] Tests pass
- [ ] Linter passes
- [ ] New code has tests
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] No secrets or credentials in code

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No security issues
```

## Security

### Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Email security concerns to: security@example.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Guidelines

When contributing:

- Never commit credentials or secrets
- Validate all user input
- Use parameterized commands (no shell injection)
- Follow least privilege principle
- Add rate limiting for new actions
- Protect system accounts and processes

## Questions?

- Open a GitHub Discussion for questions
- Check existing issues before creating new ones
- Join our community chat (if available)

Thank you for contributing to AISAC Agent!
