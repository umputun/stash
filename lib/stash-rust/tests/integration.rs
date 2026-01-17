use stash::{Client, ClientOptions, Error, Format};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(feature = "zk")]
use std::{fs, path::Path};

#[tokio::test]
async fn test_ping() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.ping().await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/test/key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("test value"))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get("test/key").await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "test value");
}

#[tokio::test]
async fn test_get_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get("missing").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::NotFound));
}

#[tokio::test]
async fn test_get_bytes() {
    let mock_server = MockServer::start().await;

    let binary_data = vec![0x00, 0x01, 0x02, 0xFF];
    Mock::given(method("GET"))
        .and(path("/kv/binary"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(binary_data.clone()))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get_bytes("binary").await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), binary_data);
}

#[tokio::test]
async fn test_get_or_default() {
    let mock_server = MockServer::start().await;

    // successful get
    Mock::given(method("GET"))
        .and(path("/kv/exists"))
        .respond_with(ResponseTemplate::new(200).set_body_string("value"))
        .mount(&mock_server)
        .await;

    // not found
    Mock::given(method("GET"))
        .and(path("/kv/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();

    let result = client.get_or_default("exists", "default").await;
    assert_eq!(result, "value");

    let result = client.get_or_default("missing", "default").await;
    assert_eq!(result, "default");
}

#[tokio::test]
async fn test_set() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/kv/test/key"))
        .and(query_param("format", "json"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client
        .set("test/key", "test value", Some(Format::Json))
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_set_without_format() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/kv/test/key"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.set("test/key", "test value", None).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_set_bytes() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/kv/binary"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let binary_data = vec![0x00, 0x01, 0x02, 0xFF];
    let result = client.set_bytes("binary", &binary_data, None).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete() {
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/kv/test/key"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.delete("test/key").await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/kv/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.delete("missing").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::NotFound));
}

#[tokio::test]
async fn test_list() {
    let mock_server = MockServer::start().await;

    let keys_json = r#"[
        {
            "key": "app/config",
            "size": 100,
            "format": "json",
            "created": "2025-01-01T00:00:00Z",
            "updated": "2025-01-01T00:00:00Z",
            "secret": false,
            "zkEncrypted": false
        },
        {
            "key": "app/database",
            "size": 200,
            "format": "yaml",
            "created": "2025-01-01T00:00:00Z",
            "updated": "2025-01-01T00:00:00Z",
            "secret": true,
            "zkEncrypted": false
        }
    ]"#;

    Mock::given(method("GET"))
        .and(path("/kv/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(keys_json))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.list(None).await;

    assert!(result.is_ok());
    let keys = result.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].key, "app/config");
    assert_eq!(keys[0].size, 100);
    assert_eq!(keys[0].format, Format::Json);
    assert!(!keys[0].secret);
    assert_eq!(keys[1].key, "app/database");
    assert_eq!(keys[1].size, 200);
    assert_eq!(keys[1].format, Format::Yaml);
    assert!(keys[1].secret);
}

#[tokio::test]
async fn test_list_with_prefix() {
    let mock_server = MockServer::start().await;

    let keys_json = r#"[
        {
            "key": "app/config",
            "size": 100,
            "format": "text",
            "created": "2025-01-01T00:00:00Z",
            "updated": "2025-01-01T00:00:00Z",
            "secret": false,
            "zkEncrypted": false
        }
    ]"#;

    Mock::given(method("GET"))
        .and(path("/kv/"))
        .and(query_param("prefix", "app/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(keys_json))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.list(Some("app/")).await;

    assert!(result.is_ok());
    let keys = result.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].key, "app/config");
}

#[tokio::test]
async fn test_info() {
    let mock_server = MockServer::start().await;

    let keys_json = r#"[
        {
            "key": "app/config",
            "size": 100,
            "format": "json",
            "created": "2025-01-01T00:00:00Z",
            "updated": "2025-01-01T00:00:00Z",
            "secret": false,
            "zkEncrypted": false
        }
    ]"#;

    Mock::given(method("GET"))
        .and(path("/kv/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(keys_json))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.info("app/config").await;

    assert!(result.is_ok());
    let info = result.unwrap();
    assert_eq!(info.key, "app/config");
    assert_eq!(info.size, 100);
}

#[tokio::test]
async fn test_info_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.info("missing").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::NotFound));
}

#[tokio::test]
async fn test_client_with_token() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&mock_server)
        .await;

    let opts = ClientOptions {
        token: Some("test-token".to_string()),
        ..Default::default()
    };

    let client = Client::with_options(&mock_server.uri(), opts).unwrap();
    let result = client.ping().await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_client_with_invalid_zk_key() {
    let opts = ClientOptions {
        zk_key: Some("short".to_string()), // less than 16 chars
        ..Default::default()
    };

    let result = Client::with_options("http://localhost:8080", opts);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/test"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get("test").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::Unauthorized));
}

#[tokio::test]
async fn test_forbidden() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/secret"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get("secret").await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::Forbidden));
}

#[tokio::test]
async fn test_subscribe_empty_key() {
    let client = Client::new("http://localhost:8080").unwrap();
    let result = client.subscribe("").await;
    assert!(result.is_err());
    match result {
        Err(Error::Connection(msg)) => assert!(msg.contains("key cannot be empty")),
        _ => panic!("expected Connection error"),
    }
}

#[tokio::test]
async fn test_subscribe_prefix_empty() {
    let client = Client::new("http://localhost:8080").unwrap();
    let result = client.subscribe_prefix("").await;
    assert!(result.is_err());
    match result {
        Err(Error::Connection(msg)) => assert!(msg.contains("prefix cannot be empty")),
        _ => panic!("expected Connection error"),
    }
}

#[tokio::test]
async fn test_subscribe_single_event() {
    use futures::StreamExt;

    let mock_server = MockServer::start().await;

    // create SSE response with a single event
    let sse_data = r#"data: {"key":"app/config","action":"update","timestamp":"2025-01-16T10:00:00Z"}

"#;

    Mock::given(method("GET"))
        .and(path("/kv/subscribe/app/config"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_data)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let mut stream = client.subscribe("app/config").await.unwrap();

    // read first event
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .expect("timeout waiting for event")
        .expect("stream should have an event")
        .expect("event should parse successfully");

    assert_eq!(event.key, "app/config");
    assert_eq!(event.action, "update");
}

#[tokio::test]
async fn test_subscribe_multiple_events() {
    use futures::StreamExt;

    let mock_server = MockServer::start().await;

    // create SSE response with multiple events
    let sse_data = r#"data: {"key":"app/config","action":"create","timestamp":"2025-01-16T10:00:00Z"}

data: {"key":"app/database","action":"update","timestamp":"2025-01-16T10:00:01Z"}

data: {"key":"app/config","action":"delete","timestamp":"2025-01-16T10:00:02Z"}

"#;

    Mock::given(method("GET"))
        .and(path("/kv/subscribe/app/*"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_data)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let mut stream = client.subscribe_prefix("app").await.unwrap();

    // read first event
    let event1 = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .expect("timeout")
        .expect("should have event")
        .expect("should parse");
    assert_eq!(event1.key, "app/config");
    assert_eq!(event1.action, "create");

    // read second event
    let event2 = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .expect("timeout")
        .expect("should have event")
        .expect("should parse");
    assert_eq!(event2.key, "app/database");
    assert_eq!(event2.action, "update");

    // read third event
    let event3 = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .expect("timeout")
        .expect("should have event")
        .expect("should parse");
    assert_eq!(event3.key, "app/config");
    assert_eq!(event3.action, "delete");
}

#[tokio::test]
async fn test_subscribe_with_token() {
    use futures::StreamExt;
    use wiremock::matchers::header;

    let mock_server = MockServer::start().await;

    let sse_data = r#"data: {"key":"secret/key","action":"update","timestamp":"2025-01-16T10:00:00Z"}

"#;

    Mock::given(method("GET"))
        .and(path("/kv/subscribe/secret/key"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(sse_data)
                .insert_header("content-type", "text/event-stream"),
        )
        .mount(&mock_server)
        .await;

    let opts = ClientOptions {
        token: Some("test-token".to_string()),
        ..Default::default()
    };

    let client = Client::with_options(&mock_server.uri(), opts).unwrap();
    let mut stream = client.subscribe("secret/key").await.unwrap();

    let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .expect("timeout")
        .expect("should have event")
        .expect("should parse");

    assert_eq!(event.key, "secret/key");
    assert_eq!(event.action, "update");
}

// ZK cross-compatibility tests
// these tests verify that Rust SDK can interoperate with Go, Python, and TypeScript SDKs

#[cfg(feature = "zk")]
#[test]
#[ignore]
fn test_zk_generate_rust_fixture() {
    // generates encrypted fixture for other SDKs to decrypt
    // run with: cargo test --features zk test_zk_generate_rust_fixture -- --ignored
    // fixture files are committed to the repo for other SDKs to use
    use stash::zk::ZKCrypto;

    const PASSPHRASE: &str = "cross-compat-key-16";
    const PLAINTEXT: &str = "hello from Rust! 🦀";
    const FIXTURE_PATH: &str = "../stash-python/tests/fixtures/";

    let zk = ZKCrypto::new(PASSPHRASE).unwrap();
    let encrypted = zk.encrypt(PLAINTEXT.as_bytes()).unwrap();

    // create fixtures directory if it doesn't exist
    fs::create_dir_all(FIXTURE_PATH).unwrap();

    // write encrypted data
    fs::write(
        Path::new(FIXTURE_PATH).join("rust_encrypted.bin"),
        encrypted.as_bytes(),
    )
    .unwrap();

    // write plaintext for reference
    fs::write(
        Path::new(FIXTURE_PATH).join("rust_plaintext.txt"),
        PLAINTEXT.as_bytes(),
    )
    .unwrap();

    println!("generated fixtures in {}", FIXTURE_PATH);
    println!("encrypted: {}", encrypted);
}

#[cfg(feature = "zk")]
#[test]
fn test_zk_decrypt_go_fixture() {
    // decrypts fixture generated by Go for cross-compatibility verification
    use stash::zk::ZKCrypto;

    const PASSPHRASE: &str = "cross-compat-key-16";
    const FIXTURE_PATH: &str = "../stash-python/tests/fixtures/";

    let encrypted_path = Path::new(FIXTURE_PATH).join("go_encrypted.bin");
    if !encrypted_path.exists() {
        println!(
            "go fixture not found at {:?}, skipping test",
            encrypted_path
        );
        return;
    }

    let encrypted = fs::read_to_string(&encrypted_path).unwrap();
    let expected_plaintext = fs::read_to_string(Path::new(FIXTURE_PATH).join("go_plaintext.txt"))
        .unwrap()
        .trim()
        .to_string();

    let zk = ZKCrypto::new(PASSPHRASE).unwrap();
    let decrypted = zk.decrypt(&encrypted).unwrap();
    let decrypted_str = String::from_utf8(decrypted).unwrap();

    assert_eq!(decrypted_str, expected_plaintext);
    println!("successfully decrypted Go fixture: {}", decrypted_str);
}

#[cfg(feature = "zk")]
#[test]
fn test_zk_decrypt_python_fixture() {
    // decrypts fixture generated by Python for cross-compatibility verification
    use stash::zk::ZKCrypto;

    const PASSPHRASE: &str = "cross-compat-key-16";
    const FIXTURE_PATH: &str = "../stash-python/tests/fixtures/";

    let encrypted_path = Path::new(FIXTURE_PATH).join("python_encrypted.bin");
    if !encrypted_path.exists() {
        println!(
            "python fixture not found at {:?}, skipping test",
            encrypted_path
        );
        return;
    }

    let encrypted = fs::read_to_string(&encrypted_path).unwrap();
    let expected_plaintext =
        fs::read_to_string(Path::new(FIXTURE_PATH).join("python_plaintext.txt"))
            .unwrap()
            .trim()
            .to_string();

    let zk = ZKCrypto::new(PASSPHRASE).unwrap();
    let decrypted = zk.decrypt(&encrypted).unwrap();
    let decrypted_str = String::from_utf8(decrypted).unwrap();

    assert_eq!(decrypted_str, expected_plaintext);
    println!("successfully decrypted Python fixture: {}", decrypted_str);
}

#[cfg(feature = "zk")]
#[tokio::test]
async fn test_zk_integration_with_mock_server() {
    // test ZK encryption/decryption with mock server
    use stash::zk::is_zk_encrypted;

    let mock_server = MockServer::start().await;

    // create client with ZK key
    let opts = ClientOptions {
        zk_key: Some("test-passphrase-16".to_string()),
        ..Default::default()
    };
    let client = Client::with_options(&mock_server.uri(), opts).unwrap();

    // mock the set endpoint
    Mock::given(method("PUT"))
        .and(path("/kv/secret/key"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    // set a value (should be encrypted)
    let original_value = "secret data";
    let result = client.set("secret/key", original_value, None).await;
    assert!(result.is_ok());

    // verify the request body was encrypted
    let received_requests = mock_server.received_requests().await.unwrap();
    let last_request = received_requests.last().unwrap();
    let body = String::from_utf8(last_request.body.clone()).unwrap();
    assert!(is_zk_encrypted(&body), "body should be ZK encrypted");

    // mock the get endpoint to return encrypted data
    Mock::given(method("GET"))
        .and(path("/kv/secret/key"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&mock_server)
        .await;

    // get the value (should be decrypted)
    let retrieved = client.get("secret/key").await.unwrap();
    assert_eq!(retrieved, original_value);
}
