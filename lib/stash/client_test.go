package stash

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("valid base URL", func(t *testing.T) {
		c, err := New("http://localhost:8080")
		require.NoError(t, err)
		assert.Equal(t, "http://localhost:8080", c.baseURL)
		assert.NotNil(t, c.requester)
	})

	t.Run("trailing slash removed", func(t *testing.T) {
		c, err := New("http://localhost:8080/")
		require.NoError(t, err)
		assert.Equal(t, "http://localhost:8080", c.baseURL)
	})

	t.Run("empty base URL", func(t *testing.T) {
		_, err := New("")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "base URL is required")
	})

	t.Run("with options", func(t *testing.T) {
		// options are applied during construction, verify client is created successfully
		customClient := &http.Client{Timeout: 10 * time.Second}
		c, err := New("http://localhost:8080",
			WithToken("token123"),
			WithTimeout(10*time.Second),
			WithRetry(2, 50*time.Millisecond),
			WithHTTPClient(customClient),
		)
		require.NoError(t, err)
		assert.NotNil(t, c.requester)
	})
}

func TestClient_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/kv/app/config", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"debug": true}`))
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		val, err := c.Get(context.Background(), "app/config")
		require.NoError(t, err)
		assert.Equal(t, `{"debug": true}`, val)
	})

	t.Run("not found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		_, err = c.Get(context.Background(), "missing")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("unauthorized", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		_, err = c.Get(context.Background(), "key")
		require.ErrorIs(t, err, ErrUnauthorized)
	})

	t.Run("forbidden", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		_, err = c.Get(context.Background(), "key")
		require.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("empty key", func(t *testing.T) {
		c, err := New("http://localhost:8080")
		require.NoError(t, err)

		_, err = c.Get(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is required")
	})

	t.Run("with auth token", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer secret-token", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("value"))
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithToken("secret-token"), WithRetry(0, 0))
		require.NoError(t, err)

		val, err := c.Get(context.Background(), "key")
		require.NoError(t, err)
		assert.Equal(t, "value", val)
	})
}

func TestClient_GetOrDefault(t *testing.T) {
	t.Run("key exists", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("actual value"))
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		val, err := c.GetOrDefault(context.Background(), "key", "default")
		require.NoError(t, err)
		assert.Equal(t, "actual value", val)
	})

	t.Run("key not found returns default", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		val, err := c.GetOrDefault(context.Background(), "missing", "fallback")
		require.NoError(t, err)
		assert.Equal(t, "fallback", val)
	})

	t.Run("other errors propagate", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		_, err = c.GetOrDefault(context.Background(), "key", "default")
		require.ErrorIs(t, err, ErrUnauthorized)
	})
}

func TestClient_GetBytes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0x00, 0x01, 0xFF, 0xFE})
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		val, err := c.GetBytes(context.Background(), "binary")
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0x01, 0xFF, 0xFE}, val)
	})

	t.Run("empty key", func(t *testing.T) {
		c, err := New("http://localhost:8080")
		require.NoError(t, err)

		_, err = c.GetBytes(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is required")
	})
}

func TestClient_Set(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "/kv/app/config", r.URL.Path)

			body, _ := io.ReadAll(r.Body)
			assert.Equal(t, `{"debug": true}`, string(body))

			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		err = c.Set(context.Background(), "app/config", `{"debug": true}`)
		require.NoError(t, err)
	})

	t.Run("empty key", func(t *testing.T) {
		c, err := New("http://localhost:8080")
		require.NoError(t, err)

		err = c.Set(context.Background(), "", "value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is required")
	})

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		err = c.Set(context.Background(), "key", "value")
		require.Error(t, err)

		var respErr *ResponseError
		require.ErrorAs(t, err, &respErr)
		assert.Equal(t, http.StatusInternalServerError, respErr.StatusCode)
	})
}

func TestClient_SetWithFormat(t *testing.T) {
	t.Run("with format", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "json", r.Header.Get("X-Stash-Format"))
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		err = c.SetWithFormat(context.Background(), "key", `{}`, FormatJSON)
		require.NoError(t, err)
	})

	t.Run("empty key", func(t *testing.T) {
		c, err := New("http://localhost:8080")
		require.NoError(t, err)

		err = c.SetWithFormat(context.Background(), "", "value", FormatJSON)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is required")
	})
}

func TestClient_Delete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "/kv/app/config", r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		err = c.Delete(context.Background(), "app/config")
		require.NoError(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		err = c.Delete(context.Background(), "missing")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("empty key", func(t *testing.T) {
		c, err := New("http://localhost:8080")
		require.NoError(t, err)

		err = c.Delete(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is required")
	})
}

func TestClient_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		keys := []KeyInfo{
			{Key: "app/config", Size: 100, Format: "json", CreatedAt: time.Now(), UpdatedAt: time.Now()},
			{Key: "app/db", Size: 50, Format: "yaml", CreatedAt: time.Now(), UpdatedAt: time.Now()},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/kv/", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(keys)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		result, err := c.List(context.Background(), "")
		require.NoError(t, err)
		assert.Len(t, result, 2)
		assert.Equal(t, "app/config", result[0].Key)
		assert.Equal(t, "app/db", result[1].Key)
	})

	t.Run("with prefix", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "app/", r.URL.Query().Get("prefix"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		_, err = c.List(context.Background(), "app/")
		require.NoError(t, err)
	})

	t.Run("empty result", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		result, err := c.List(context.Background(), "")
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestClient_Info(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		keys := []KeyInfo{
			{Key: "app/config", Size: 100, Format: "json", CreatedAt: now, UpdatedAt: now},
			{Key: "app/config/nested", Size: 50, Format: "yaml", CreatedAt: now, UpdatedAt: now},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(keys)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		info, err := c.Info(context.Background(), "app/config")
		require.NoError(t, err)
		assert.Equal(t, "app/config", info.Key)
		assert.Equal(t, 100, info.Size)
		assert.Equal(t, "json", info.Format)
	})

	t.Run("not found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		_, err = c.Info(context.Background(), "missing")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("empty key", func(t *testing.T) {
		c, err := New("http://localhost:8080")
		require.NoError(t, err)

		_, err = c.Info(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is required")
	})
}

func TestClient_Ping(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "/ping", r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("pong"))
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		err = c.Ping(context.Background())
		require.NoError(t, err)
	})

	t.Run("server down", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		err = c.Ping(context.Background())
		require.Error(t, err)

		var respErr *ResponseError
		require.ErrorAs(t, err, &respErr)
		assert.Equal(t, http.StatusServiceUnavailable, respErr.StatusCode)
	})
}

func TestResponseError_Error(t *testing.T) {
	err := &ResponseError{StatusCode: 500}
	assert.Equal(t, "stash: HTTP 500", err.Error())
}

func TestClient_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL, WithRetry(0, 0))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = c.Get(ctx, "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestClient_ConnectionError(t *testing.T) {
	c, err := New("http://127.0.0.1:59999", WithRetry(0, 0)) // non-existent port
	require.NoError(t, err)

	_, err = c.Get(context.Background(), "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

func TestClient_List_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer srv.Close()

	c, err := New(srv.URL, WithRetry(0, 0))
	require.NoError(t, err)

	_, err = c.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response")
}

func TestClient_Info_ListError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := New(srv.URL, WithRetry(0, 0))
	require.NoError(t, err)

	_, err = c.Info(context.Background(), "key")
	require.Error(t, err)
}

func TestClient_Set_DefaultFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "text", r.Header.Get("X-Stash-Format"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL, WithRetry(0, 0))
	require.NoError(t, err)

	err = c.Set(context.Background(), "key", "value")
	require.NoError(t, err)
}

func TestClient_ZKEncryption(t *testing.T) {
	const passphrase = "test-passphrase-16"

	t.Run("WithZKKey creates client with encryption", func(t *testing.T) {
		c, err := New("http://localhost", WithZKKey(passphrase))
		require.NoError(t, err)
		assert.NotNil(t, c.zkCrypto)
	})

	t.Run("WithZKKey rejects short passphrase", func(t *testing.T) {
		_, err := New("http://localhost", WithZKKey("short"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "passphrase")
	})

	t.Run("Set encrypts value before sending", func(t *testing.T) {
		var receivedBody string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			receivedBody = string(body)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0), WithZKKey(passphrase))
		require.NoError(t, err)

		err = c.Set(context.Background(), "secret/key", "plaintext value")
		require.NoError(t, err)

		// verify body starts with $ZK$ prefix
		assert.Greater(t, len(receivedBody), 4, "body should not be empty")
		assert.Equal(t, "$ZK$", receivedBody[:4], "body should start with $ZK$ prefix")
		assert.NotEqual(t, "plaintext value", receivedBody, "value should be encrypted")
	})

	t.Run("Get decrypts $ZK$ value", func(t *testing.T) {
		// first encrypt a value
		zk, err := NewZKCrypto([]byte(passphrase))
		require.NoError(t, err)
		encrypted, err := zk.Encrypt([]byte("secret message"))
		require.NoError(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(encrypted)
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0), WithZKKey(passphrase))
		require.NoError(t, err)

		val, err := c.Get(context.Background(), "secret/key")
		require.NoError(t, err)
		assert.Equal(t, "secret message", val)
	})

	t.Run("Get returns raw value when no ZK key configured", func(t *testing.T) {
		// create encrypted value
		zk, err := NewZKCrypto([]byte(passphrase))
		require.NoError(t, err)
		encrypted, err := zk.Encrypt([]byte("secret message"))
		require.NoError(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(encrypted)
		}))
		defer srv.Close()

		// client WITHOUT ZK key
		c, err := New(srv.URL, WithRetry(0, 0))
		require.NoError(t, err)

		val, err := c.Get(context.Background(), "secret/key")
		require.NoError(t, err)
		// should return raw $ZK$ prefixed value
		assert.True(t, len(val) > 4 && val[:4] == "$ZK$", "should return raw encrypted value")
	})

	t.Run("Get fails with wrong passphrase", func(t *testing.T) {
		// encrypt with one passphrase
		zk, err := NewZKCrypto([]byte(passphrase))
		require.NoError(t, err)
		encrypted, err := zk.Encrypt([]byte("secret message"))
		require.NoError(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(encrypted)
		}))
		defer srv.Close()

		// client with DIFFERENT passphrase
		c, err := New(srv.URL, WithRetry(0, 0), WithZKKey("different-pass-16"))
		require.NoError(t, err)

		_, err = c.Get(context.Background(), "secret/key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decrypt")
	})

	t.Run("round-trip Set then Get", func(t *testing.T) {
		var storedValue []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPut {
				storedValue, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == http.MethodGet {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(storedValue)
				return
			}
		}))
		defer srv.Close()

		c, err := New(srv.URL, WithRetry(0, 0), WithZKKey(passphrase))
		require.NoError(t, err)

		// set a value
		err = c.Set(context.Background(), "test/key", "my secret data")
		require.NoError(t, err)

		// verify stored value is encrypted
		assert.True(t, len(storedValue) > 4 && string(storedValue[:4]) == "$ZK$")

		// get it back
		val, err := c.Get(context.Background(), "test/key")
		require.NoError(t, err)
		assert.Equal(t, "my secret data", val)
	})
}

func TestClient_Close(t *testing.T) {
	t.Run("with ZK enabled", func(t *testing.T) {
		c, err := New("http://test", WithRetry(0, 0), WithZKKey("test-passphrase-16"))
		require.NoError(t, err)
		c.Close() // should not panic
	})

	t.Run("without ZK", func(t *testing.T) {
		c, err := New("http://test", WithRetry(0, 0))
		require.NoError(t, err)
		c.Close() // should not panic with nil zkCrypto
	})
}

func TestClient_SetWithFormat_ZKEncryption(t *testing.T) {
	passphrase := "test-passphrase-min-16"

	var storedValue []byte
	var storedFormat string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			storedValue, _ = io.ReadAll(r.Body)
			storedFormat = r.Header.Get("X-Stash-Format")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(storedValue)
			return
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, WithRetry(0, 0), WithZKKey(passphrase))
	require.NoError(t, err)
	defer c.Close()

	// set a value with format
	err = c.SetWithFormat(context.Background(), "config/db", `{"host":"localhost"}`, FormatJSON)
	require.NoError(t, err)

	// verify stored value is encrypted
	assert.True(t, len(storedValue) > 4 && string(storedValue[:4]) == "$ZK$", "value should be ZK-encrypted")
	assert.Equal(t, "json", storedFormat, "format should be passed to server")

	// get it back
	val, err := c.Get(context.Background(), "config/db")
	require.NoError(t, err)
	assert.JSONEq(t, `{"host":"localhost"}`, val, "decrypted value should match original")
}
