# Developer Checklist

Use this checklist before submitting any code to ensure compliance with project standards.

## Before Writing Code

- [ ] Read relevant standards documents
- [ ] Understand the component interfaces
- [ ] Review existing code in the package
- [ ] Plan the implementation approach

## While Writing Code

### General
- [ ] Context as first parameter in all functions
- [ ] Errors as last return value
- [ ] All errors wrapped with context
- [ ] All resources have deferred cleanup
- [ ] No hardcoded values (use constants)

### Functions
- [ ] Functions do one thing
- [ ] Function names are descriptive
- [ ] Complex functions have comments
- [ ] No functions longer than 50 lines

### Error Handling
- [ ] Used standard error types where applicable
- [ ] Errors wrapped with `fmt.Errorf` and `%w`
- [ ] Error messages are lowercase
- [ ] Errors provide enough context

### Testing
- [ ] Unit tests for all new functions
- [ ] Table-driven tests for multiple cases
- [ ] Test names describe scenario
- [ ] Edge cases covered
- [ ] Error paths tested

### Concurrency
- [ ] Goroutines have proper lifecycle management
- [ ] Channels have clear ownership
- [ ] No goroutine leaks
- [ ] Race conditions checked

### Documentation
- [ ] Public APIs have godoc comments
- [ ] Complex logic has explanatory comments
- [ ] Package has README if needed
- [ ] Examples provided for public APIs

## Before Committing

### Code Quality
- [ ] Run `go fmt ./...`
- [ ] Run `go vet ./...`
- [ ] Run `golangci-lint run`
- [ ] Run `go test ./...`
- [ ] Check test coverage

### Git
- [ ] Commit message follows format
- [ ] Commit is focused (one logical change)
- [ ] No commented-out code
- [ ] No debug prints left

## Before Creating PR

### Final Checks
- [ ] All tests pass locally
- [ ] Code follows all standards
- [ ] PR description is complete
- [ ] Breaking changes documented
- [ ] Related issues referenced

### PR Description Includes
- [ ] What the change does
- [ ] Why it's needed
- [ ] How it was tested
- [ ] Any risks or concerns

## Code Review Response

- [ ] Address all comments
- [ ] Explain any disagreements respectfully
- [ ] Update code based on feedback
- [ ] Thank reviewers

## Common Mistakes to Avoid

1. **Forgetting context parameter**
   ```go
   // ❌ Wrong
   func GetFile(id string) (*File, error)
   
   // ✅ Correct
   func GetFile(ctx context.Context, id string) (*File, error)
   ```

2. **Not wrapping errors**
   ```go
   // ❌ Wrong
   if err != nil {
       return err
   }
   
   // ✅ Correct
   if err != nil {
       return fmt.Errorf("failed to process file %s: %w", id, err)
   }
   ```

3. **Forgetting cleanup**
   ```go
   // ❌ Wrong
   file, err := os.Open(path)
   
   // ✅ Correct
   file, err := os.Open(path)
   if err != nil {
       return err
   }
   defer file.Close()
   ```

4. **No input validation**
   ```go
   // ❌ Wrong
   func Process(data string) error {
       // Use data directly
   }
   
   // ✅ Correct
   func Process(data string) error {
       if data == "" {
           return fmt.Errorf("data cannot be empty: %w", ErrInvalidInput)
       }
       // Process validated data
   }
   ```

5. **Poor test names**
   ```go
   // ❌ Wrong
   func TestProcess(t *testing.T)
   
   // ✅ Correct
   func TestProcess_WithValidInput_ReturnsSuccess(t *testing.T)
   func TestProcess_WithEmptyInput_ReturnsError(t *testing.T)
   ```

Print this checklist and keep it handy!