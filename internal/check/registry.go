package check

// registry maps command names to their Checker.
var registry = map[string]Checker{}

// Register maps one or more command names to a Checker implementation.
// Called by checker packages in init() functions.
func Register(c Checker, names ...string) {
	for _, name := range names {
		registry[name] = c
	}
}

// Lookup returns the Checker registered for the given command name.
func Lookup(name string) (Checker, bool) {
	c, ok := registry[name]
	return c, ok
}
