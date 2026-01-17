use stash::{Client, ClientOptions, Error, Format};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
