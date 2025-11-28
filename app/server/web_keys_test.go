package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
	"github.com/umputun/stash/app/validator"
)

func TestHandleKeyList(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{
				{Key: "alpha", Size: 50},
				{Key: "beta", Size: 100},
			}, nil
		},
	}
	srv := newTestServer(t, st)

	t.Run("returns key list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "alpha")
		assert.Contains(t, rec.Body.String(), "beta")
	})

	t.Run("filters with search", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys?search=alpha", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "alpha")
		assert.NotContains(t, rec.Body.String(), ">beta<")
	})
}

func TestHandleKeyNew(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Create Key")
}

func TestHandleKeyView(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			if key == "testkey" {
				return []byte("testvalue"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	t.Run("existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "testvalue")
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/missing", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHandleKeyEdit(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			if key == "editkey" {
				return []byte("editvalue"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		GetInfoFunc: func(key string) (store.KeyInfo, error) {
			return store.KeyInfo{Key: key, UpdatedAt: time.Now()}, nil
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	t.Run("existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/editkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "editvalue")
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/missing", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHandleKeyCreate(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
		SetFunc:           func(key string, value []byte, format string) error { return nil },
		ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{
		"key":   {"newkey"},
		"value": {"newvalue"},
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, st.SetCalls(), 1)
	assert.Equal(t, "newkey", st.SetCalls()[0].Key)
	assert.Equal(t, "newvalue", string(st.SetCalls()[0].Value))
}

func TestHandleKeyUpdate(t *testing.T) {
	st := &mocks.KVStoreMock{
		SetFunc:  func(key string, value []byte, format string) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodPut, "/web/keys/updatekey", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{
		"value": {"updated"},
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, st.SetCalls(), 1)
	assert.Equal(t, "updatekey", st.SetCalls()[0].Key)
	assert.Equal(t, "updated", string(st.SetCalls()[0].Value))
}

func TestHandleKeyDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/deletekey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.DeleteCalls(), 1)
		assert.Equal(t, "deletekey", st.DeleteCalls()[0].Key)
	})

	t.Run("not found", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return store.ErrNotFound },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/missing", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("internal error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return errors.New("db error") },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/errorkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandleKeyCreate_Errors(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {""}, "value": {"val"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, st.SetCalls())
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
			SetFunc:           func(key string, value []byte, format string) error { return errors.New("db error") },
			ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"testkey"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("duplicate key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(key string) ([]byte, string, error) { return []byte("existing"), "text", nil },
			SetFunc:           func(key string, value []byte, format string) error { return nil },
			ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"existing-key"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code) // form re-rendered with error
		body := rec.Body.String()
		assert.Contains(t, body, "already exists")
		assert.Empty(t, st.SetCalls(), "Set should not be called for duplicate key")
		// verify save button is visible and no force button (can't force duplicate)
		assert.Contains(t, body, `id="save-btn"`)
		assert.NotContains(t, body, `id="force-btn"`)
	})
}

func TestHandleKeyUpdate_Errors(t *testing.T) {
	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return errors.New("db error") },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandleKeyCreate_Validation(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		value      string
		force      string
		wantSet    bool // whether Set should be called
		wantStatus int
	}{
		{name: "valid json saves", format: "json", value: `{"key":"value"}`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid json returns error", format: "json", value: `{bad json}`, force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid json with force saves", format: "json", value: `{bad json}`, force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "valid yaml saves", format: "yaml", value: "key: value", force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid yaml returns error", format: "yaml", value: "key:\n\tbad", force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid yaml with force saves", format: "yaml", value: "key:\n\tbad", force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "text bypasses validation", format: "text", value: `{not valid json but who cares}`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "shell bypasses validation", format: "shell", value: `echo $VAR`, force: "", wantSet: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &mocks.KVStoreMock{
				GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
				SetFunc:           func(key string, value []byte, format string) error { return nil },
				ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
			}
			srv := newTestServer(t, st)

			form := map[string][]string{
				"key":    {"testkey"},
				"value":  {tt.value},
				"format": {tt.format},
			}
			if tt.force != "" {
				form["force"] = []string{tt.force}
			}

			req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.PostForm = form
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantSet {
				require.Len(t, st.SetCalls(), 1, "expected Set to be called")
				assert.Equal(t, "testkey", st.SetCalls()[0].Key)
			} else {
				assert.Empty(t, st.SetCalls(), "expected Set NOT to be called")
				// verify error message is in response (form re-rendered with error)
				body := rec.Body.String()
				assert.Contains(t, body, "invalid")
				// verify save button is hidden and force button is shown
				assert.Contains(t, body, `id="save-btn"`)
				assert.Contains(t, body, `style="display:none"`)
				assert.Contains(t, body, `id="force-btn"`)
			}
		})
	}
}

func TestHandleKeyUpdate_Validation(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		value      string
		force      string
		wantSet    bool
		wantStatus int
	}{
		{name: "valid json saves", format: "json", value: `["item1","item2"]`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid json returns error", format: "json", value: `[missing bracket`, force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid json with force saves", format: "json", value: `[missing bracket`, force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "valid toml saves", format: "toml", value: `key = "value"`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid toml returns error", format: "toml", value: `key "no equals"`, force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid toml with force saves", format: "toml", value: `key "no equals"`, force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "text bypasses validation", format: "text", value: `anything goes here`, force: "", wantSet: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &mocks.KVStoreMock{
				SetFunc: func(key string, value []byte, format string) error { return nil },
				GetInfoFunc: func(key string) (store.KeyInfo, error) {
					return store.KeyInfo{Key: key, UpdatedAt: time.Now()}, nil
				},
				ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
			}
			srv := newTestServer(t, st)

			form := map[string][]string{
				"value":  {tt.value},
				"format": {tt.format},
			}
			if tt.force != "" {
				form["force"] = []string{tt.force}
			}

			req := httptest.NewRequest(http.MethodPut, "/web/keys/updatekey", http.NoBody)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.PostForm = form
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantSet {
				require.Len(t, st.SetCalls(), 1, "expected Set to be called")
				assert.Equal(t, "updatekey", st.SetCalls()[0].Key)
			} else {
				assert.Empty(t, st.SetCalls(), "expected Set NOT to be called")
				body := rec.Body.String()
				assert.Contains(t, body, "invalid")
				// verify save button is hidden and force button is shown
				assert.Contains(t, body, `id="save-btn"`)
				assert.Contains(t, body, `style="display:none"`)
				assert.Contains(t, body, `id="force-btn"`)
			}
		})
	}
}

func TestHandleKeyUpdate_ConflictDetection(t *testing.T) {
	originalTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	modifiedTime := time.Date(2024, 1, 1, 12, 5, 0, 0, time.UTC) // 5 minutes later

	t.Run("conflict detected when timestamp differs", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: modifiedTime}, nil // server has newer timestamp
			},
			GetWithFormatFunc: func(key string) ([]byte, string, error) {
				return []byte("server value"), "text", nil
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":      {"my edited value"},
			"format":     {"text"},
			"updated_at": {fmt.Sprintf("%d", originalTime.Unix())}, // old timestamp
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, st.SetCalls(), "expected Set NOT to be called on conflict")
		body := rec.Body.String()
		assert.Contains(t, body, "Conflict detected")
		assert.Contains(t, body, "server value")
		assert.Contains(t, body, "Reload")
		assert.Contains(t, body, "Overwrite")
	})

	t.Run("no conflict when timestamps match", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: originalTime}, nil
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":      {"my edited value"},
			"format":     {"text"},
			"updated_at": {fmt.Sprintf("%d", originalTime.Unix())},
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1, "expected Set to be called")
	})

	t.Run("force_overwrite bypasses conflict check", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: modifiedTime}, nil // server has newer timestamp
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":           {"my edited value"},
			"format":          {"text"},
			"updated_at":      {fmt.Sprintf("%d", originalTime.Unix())}, // old timestamp
			"force_overwrite": {"true"},
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1, "expected Set to be called when force_overwrite=true")
	})

	t.Run("no updated_at skips conflict check", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: modifiedTime}, nil
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":  {"my edited value"},
			"format": {"text"},
			// no updated_at field
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1, "expected Set to be called without updated_at")
	})
}

func TestHandleKeyUpdate_ValidationPreservesTimestamp(t *testing.T) {
	// this test verifies that when validation fails, the form re-renders with
	// the ORIGINAL timestamp from the request, not a fresh one from the store.
	// this prevents a race condition where another user's changes could be
	// silently overwritten after a validation retry.
	originalTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	serverTime := time.Date(2024, 1, 1, 12, 10, 0, 0, time.UTC) // server has newer timestamp

	st := &mocks.KVStoreMock{
		SetFunc: func(key string, value []byte, format string) error { return nil },
		GetInfoFunc: func(key string) (store.KeyInfo, error) {
			// return ORIGINAL time first (for conflict check), then server time (simulating race)
			return store.KeyInfo{Key: key, UpdatedAt: originalTime}, nil
		},
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			return []byte("test value"), "text", nil
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	val := &mocks.ValidatorMock{
		ValidateFunc: func(format string, value []byte) error {
			return fmt.Errorf("invalid JSON") // force validation to fail
		},
	}
	srv := newTestServerWithValidator(t, st, val)

	form := url.Values{
		"value":      {"{invalid json"},
		"format":     {"json"},
		"updated_at": {fmt.Sprintf("%d", originalTime.Unix())}, // user's original timestamp
	}

	req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, st.SetCalls(), "expected Set NOT to be called on validation error")

	body := rec.Body.String()
	// the form should preserve the ORIGINAL timestamp, not the server's newer one
	assert.Contains(t, body, fmt.Sprintf(`value="%d"`, originalTime.Unix()),
		"form should preserve original timestamp for conflict detection on retry")
	assert.NotContains(t, body, fmt.Sprintf(`value="%d"`, serverTime.Unix()),
		"form should NOT use server's newer timestamp")
}

func TestHandleKeyView_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			switch key {
			case "app/config", "other/key":
				return []byte("value"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can view any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user can view any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user can view key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/app/config", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot view key outside allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandleKeyEdit_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			switch key {
			case "app/config", "other/key":
				return []byte("value"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		GetInfoFunc: func(key string) (store.KeyInfo, error) {
			return store.KeyInfo{Key: key, UpdatedAt: time.Now()}, nil
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can edit any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot edit", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("scoped user can edit key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/app/config", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot edit key outside prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandleKeyCreate_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
		SetFunc:           func(key string, value []byte, format string) error { return nil },
		ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can create any key", func(t *testing.T) {
		st.SetCalls() // reset
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"other/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot create", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"other/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})

	t.Run("scoped user can create key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"app/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot create key outside prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"other/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})
}

func TestHandleKeyUpdate_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		SetFunc:  func(key string, value []byte, format string) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can update any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/other/key", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot update", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/other/key", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})

	t.Run("scoped user can update key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/app/config", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot update key outside prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/other/key", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})
}

func TestHandleKeyDelete_PermissionEnforcement(t *testing.T) {
	authFile := createMultiUserAuthFile(t)

	t.Run("admin can delete any key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot delete", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("scoped user can delete key in allowed prefix", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/app/config", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot delete key outside prefix", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandleKeyList_PermissionFiltering(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{
				{Key: "app/config", Size: 50},
				{Key: "app/db", Size: 100},
				{Key: "other/secret", Size: 200},
			}, nil
		},
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin sees all keys", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "app/config")
		assert.Contains(t, rec.Body.String(), "app/db")
		assert.Contains(t, rec.Body.String(), "other/secret")
	})

	t.Run("readonly user sees all keys", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "app/config")
		assert.Contains(t, rec.Body.String(), "other/secret")
	})

	t.Run("scoped user sees only allowed keys", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "app/config")
		assert.Contains(t, rec.Body.String(), "app/db")
		assert.NotContains(t, rec.Body.String(), "other/secret")
	})
}

func TestHandleKeyList_MixedPermissions(t *testing.T) {
	// test that user with mixed permissions (rw on some prefixes, r on others)
	// sees Edit/Delete buttons only for keys they can write to
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{
				{Key: "app/config", Size: 50},
				{Key: "app/database", Size: 100},
				{Key: "secrets/password", Size: 20},
				{Key: "secrets/aws-key", Size: 30},
			}, nil
		},
	}
	authFile := createMixedPermAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	cookie := loginAndGetCookie(t, srv, "mixed")
	req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// user sees all keys they have access to
	assert.Contains(t, body, "app/config")
	assert.Contains(t, body, "app/database")
	assert.Contains(t, body, "secrets/password")
	assert.Contains(t, body, "secrets/aws-key")

	// action column header should be present (user has write access to some keys)
	assert.Contains(t, body, `class="actions-cell"`)

	// check that Edit buttons appear for app/* keys (rw access)
	assert.Contains(t, body, `/web/keys/edit/app%2Fconfig`)
	assert.Contains(t, body, `/web/keys/edit/app%2Fdatabase`)

	// check that Edit buttons do NOT appear for secrets/* keys (r only access)
	assert.NotContains(t, body, `/web/keys/edit/secrets%2Fpassword`)
	assert.NotContains(t, body, `/web/keys/edit/secrets%2Faws-key`)
}

func TestHandleKeyNew_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can access new key form", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Create Key")
	})

	t.Run("readonly user cannot access new key form", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("scoped user can access new key form", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestCalculateModalDimensions(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second})
	require.NoError(t, err)

	tests := []struct {
		name          string
		value         string
		wantWidth     int
		wantHeight    int
		wantWidthMin  int
		wantWidthMax  int
		wantHeightMin int
		wantHeightMax int
	}{
		{name: "empty value", value: "", wantWidth: 600, wantHeight: 104},
		{name: "short value", value: "hello", wantWidth: 600, wantHeight: 104},
		{name: "medium line 60 chars", value: "123456789012345678901234567890123456789012345678901234567890",
			wantWidth: 600, wantHeight: 104},
		{name: "long line hits max width", value: string(make([]byte, 200)),
			wantWidth: 1200, wantHeight: 104},
		{name: "few lines uses min lines", value: "line1\nline2", wantWidth: 600, wantHeight: 104},
		{name: "10 lines", value: "1\n2\n3\n4\n5\n6\n7\n8\n9\n10",
			wantWidth: 600, wantHeight: 224},
		{name: "many lines hits max height", value: "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20",
			wantWidth: 600, wantHeight: 384},
		{name: "cyrillic uses rune count not bytes", value: "привет мир",
			wantWidth: 600, wantHeight: 104},
		{name: "japanese uses rune count not bytes", value: "こんにちは世界",
			wantWidthMin: 600, wantWidthMax: 700, wantHeightMin: 104, wantHeightMax: 104},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			width, height := srv.calculateModalDimensions(tc.value)
			if tc.wantWidthMin > 0 {
				assert.GreaterOrEqual(t, width, tc.wantWidthMin, "width should be >= min")
				assert.LessOrEqual(t, width, tc.wantWidthMax, "width should be <= max")
			} else {
				assert.Equal(t, tc.wantWidth, width, "width mismatch")
			}
			if tc.wantHeightMin > 0 {
				assert.GreaterOrEqual(t, height, tc.wantHeightMin, "height should be >= min")
				assert.LessOrEqual(t, height, tc.wantHeightMax, "height should be <= max")
			} else {
				assert.Equal(t, tc.wantHeight, height, "height mismatch")
			}
		})
	}
}

func TestCheckConflict(t *testing.T) {
	now := time.Now()

	t.Run("no timestamp skips check", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		srv := newTestServer(t, st)

		conflict, err := srv.checkConflict("test-key", 0)
		require.NoError(t, err)
		assert.Nil(t, conflict)
		assert.Empty(t, st.GetInfoCalls(), "GetInfo should not be called")
	})

	t.Run("negative timestamp skips check", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		srv := newTestServer(t, st)

		conflict, err := srv.checkConflict("test-key", -1)
		require.NoError(t, err)
		assert.Nil(t, conflict)
	})

	t.Run("key not found returns no conflict", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{}, store.ErrNotFound
			},
		}
		srv := newTestServer(t, st)

		conflict, err := srv.checkConflict("test-key", now.Unix())
		require.NoError(t, err)
		assert.Nil(t, conflict)
	})

	t.Run("db error returns error", func(t *testing.T) {
		dbErr := errors.New("database connection failed")
		st := &mocks.KVStoreMock{
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{}, dbErr
			},
		}
		srv := newTestServer(t, st)

		conflict, err := srv.checkConflict("test-key", now.Unix())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to verify")
		assert.Contains(t, err.Error(), "database connection failed")
		assert.Nil(t, conflict)
	})

	t.Run("timestamps match returns no conflict", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: now}, nil
			},
		}
		srv := newTestServer(t, st)

		conflict, err := srv.checkConflict("test-key", now.Unix())
		require.NoError(t, err)
		assert.Nil(t, conflict)
	})

	t.Run("timestamps differ returns conflict", func(t *testing.T) {
		serverTime := now.Add(time.Minute)
		st := &mocks.KVStoreMock{
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: serverTime}, nil
			},
			GetWithFormatFunc: func(key string) ([]byte, string, error) {
				return []byte("server value"), "text", nil
			},
		}
		srv := newTestServer(t, st)

		conflict, err := srv.checkConflict("test-key", now.Unix())
		require.NoError(t, err)
		require.NotNil(t, conflict)
		assert.Equal(t, "server value", conflict.ServerValue)
		assert.Equal(t, "text", conflict.ServerFormat)
		assert.Equal(t, serverTime.Unix(), conflict.ServerUpdatedAt)
	})
}

func TestHandleKeyUpdate_ConflictCheckError(t *testing.T) {
	dbErr := errors.New("database unavailable")
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		GetInfoFunc: func(key string) (store.KeyInfo, error) {
			return store.KeyInfo{}, dbErr
		},
	}
	srv := newTestServer(t, st)

	form := url.Values{
		"key":        {"test-key"},
		"value":      {"test value"},
		"format":     {"text"},
		"updated_at": {"1234567890"}, // non-zero to trigger conflict check
	}
	req := httptest.NewRequest(http.MethodPut, "/web/keys/test-key", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "unable to verify")
}
