use stash::{Client, ClientOptions, Error, Format};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_client_new() {
    let client = Client::new("http://localhost:8080");
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_client_with_options() {
    let opts = ClientOptions {
        token: Some("test-token".to_string()),
        timeout: Some(std::time::Duration::from_secs(10)),
        retries: Some(5),
        zk_key: Some("test-passphrase-16".to_string()),
    };
    let client = Client::with_options("http://localhost:8080", opts);
    assert!(client.is_ok());
}

#[tokio::test]
async fn test_client_invalid_zk_key() {
    let opts = ClientOptions {
        zk_key: Some("short".to_string()),
        ..Default::default()
    };
    let result = Client::with_options("http://localhost:8080", opts);
    assert!(matches!(result, Err(Error::InvalidParameter(_))));
}

#[tokio::test]
async fn test_ping_success() {
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
async fn test_ping_failure() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ping"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.ping().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("test-value"))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get("test-key").await;
    assert_eq!(result.unwrap(), "test-value");
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
    assert!(matches!(result, Err(Error::NotFound)));
}

#[tokio::test]
async fn test_get_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/secret"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get("secret").await;
    assert!(matches!(result, Err(Error::Unauthorized)));
}

#[tokio::test]
async fn test_get_forbidden() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/restricted"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get("restricted").await;
    assert!(matches!(result, Err(Error::Forbidden)));
}

#[tokio::test]
async fn test_get_bytes_success() {
    let mock_server = MockServer::start().await;
    let test_data = vec![0x01, 0x02, 0x03, 0x04];

    Mock::given(method("GET"))
        .and(path("/kv/binary"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(test_data.clone()))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get_bytes("binary").await;
    assert_eq!(result.unwrap(), test_data);
}

#[tokio::test]
async fn test_get_or_default() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/kv/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.get_or_default("missing", "default-value").await;
    assert_eq!(result, "default-value");
}

#[tokio::test]
async fn test_set_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/kv/test-key"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.set("test-key", "test-value", None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_set_with_format() {
    let mock_server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/kv/config"))
        .and(query_param("format", "json"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client
        .set("config", r#"{"key":"value"}"#, Some(Format::Json))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_set_bytes_success() {
    let mock_server = MockServer::start().await;
    let test_data = vec![0x01, 0x02, 0x03, 0x04];

    Mock::given(method("PUT"))
        .and(path("/kv/binary"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.set_bytes("binary", &test_data, None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("DELETE"))
        .and(path("/kv/test-key"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.delete("test-key").await;
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
    assert!(matches!(result, Err(Error::NotFound)));
}

#[tokio::test]
async fn test_list_all() {
    let mock_server = MockServer::start().await;

    let response_json = r#"[
        {
            "key": "app/config",
            "size": 123,
            "format": "json",
            "secret": false,
            "zkEncrypted": false,
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-02T00:00:00Z"
        },
        {
            "key": "db/connection",
            "size": 456,
            "format": "yaml",
            "secret": true,
            "zkEncrypted": false,
            "created": "2024-01-03T00:00:00Z",
            "updated": "2024-01-04T00:00:00Z"
        }
    ]"#;

    Mock::given(method("GET"))
        .and(path("/kv/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(response_json))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.list(None).await;
    assert!(result.is_ok());
    let keys = result.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].key, "app/config");
    assert_eq!(keys[1].key, "db/connection");
    assert!(keys[1].secret);
}

#[tokio::test]
async fn test_list_with_prefix() {
    let mock_server = MockServer::start().await;

    let response_json = r#"[
        {
            "key": "app/config",
            "size": 123,
            "format": "json",
            "secret": false,
            "zkEncrypted": false,
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-02T00:00:00Z"
        }
    ]"#;

    Mock::given(method("GET"))
        .and(path("/kv/"))
        .and(query_param("prefix", "app/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(response_json))
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
async fn test_client_with_token() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ping"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200))
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
async fn test_info_success() {
    let mock_server = MockServer::start().await;

    let list_response = r#"[
        {
            "key": "test-key",
            "size": 123,
            "format": "json",
            "secret": false,
            "zkEncrypted": false,
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-02T00:00:00Z"
        }
    ]"#;

    Mock::given(method("GET"))
        .and(path("/kv/"))
        .and(query_param("prefix", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string(list_response))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.info("test-key").await;
    assert!(result.is_ok());
    let info = result.unwrap();
    assert_eq!(info.key, "test-key");
    assert_eq!(info.size, 123);
}

#[tokio::test]
async fn test_info_not_found() {
    let mock_server = MockServer::start().await;

    // info uses list with prefix, return empty array for not found
    Mock::given(method("GET"))
        .and(path("/kv/"))
        .and(query_param("prefix", "missing"))
        .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
        .mount(&mock_server)
        .await;

    let client = Client::new(&mock_server.uri()).unwrap();
    let result = client.info("missing").await;
    assert!(matches!(result, Err(Error::NotFound)));
}
