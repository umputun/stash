// Package stash provides a Go client for the Stash KV configuration service.
//
// Basic usage:
//
//	client, err := stash.New("http://localhost:8080")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// store a value (default text format)
//	err = client.Set(ctx, "app/config", `{"debug": true}`)
//
//	// store a value with explicit format
//	err = client.SetWithFormat(ctx, "app/config", `{"debug": true}`, stash.FormatJSON)
//
//	// retrieve a value
//	value, err := client.Get(ctx, "app/config")
//
//	// retrieve with default
//	value, err := client.GetOrDefault(ctx, "app/config", "fallback")
//
//	// list all keys
//	keys, err := client.List(ctx, "")
//
// With authentication:
//
//	client, err := stash.New("http://localhost:8080",
//	    stash.WithToken("your-api-token"),
//	)
//
// With custom options:
//
//	client, err := stash.New("http://localhost:8080",
//	    stash.WithToken("your-api-token"),
//	    stash.WithTimeout(10*time.Second),
//	    stash.WithRetry(5, 200*time.Millisecond),
//	)
package stash
