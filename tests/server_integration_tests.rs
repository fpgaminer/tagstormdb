use std::{path::Path, process::Stdio, sync::Arc, thread, time::Duration};

use actix_web::{dev::ServerHandle, HttpServer};
use rand::{thread_rng, Rng};
use reqwest::{Client, Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use tagstormdb::{Database, LoginKey};
use tokio::{
	io::{AsyncBufReadExt, BufReader},
	process::Command,
	sync::Mutex,
};

#[tokio::test]
async fn test_api_access_controls() {
	// Start the server
	let (mut server_process, admin_login_key, user_login_key, temp_dir, prediction_handle) = create_server().await;

	// Capture the server's stdout to get the admin password
	let stdout = server_process.stdout.take().expect("Failed to capture stdout");
	let stderr = server_process.stderr.take().expect("Failed to capture stderr");
	let server_output = Arc::new(Mutex::new(String::new()));
	{
		let server_output = server_output.clone();
		tokio::task::spawn(async move {
			let mut stdout = BufReader::new(stdout);
			loop {
				let mut line = String::new();
				stdout.read_line(&mut line).await.expect("Failed to read line from stdout");
				let mut server_output = server_output.lock().await;
				server_output.push_str(&line);
				if !line.trim().is_empty() {
					print!("{}", line);
				}
			}
		});
	}
	{
		let server_output = server_output.clone();
		tokio::task::spawn(async move {
			let mut stderr = BufReader::new(stderr);
			loop {
				let mut line = String::new();
				stderr.read_line(&mut line).await.expect("Failed to read line from stderr");
				let mut server_output = server_output.lock().await;
				server_output.push_str(&line);
				if !line.trim().is_empty() {
					print!("{}", line);
				}
			}
		});
	}

	// Wait until the server is ready
	let start = std::time::Instant::now();
	loop {
		if server_process.try_wait().unwrap().is_some() {
			thread::sleep(Duration::from_secs(5));
			panic!("Server process exited unexpectedly");
		}

		let server_output = server_output.lock().await;
		if server_output.contains("listening on:") {
			break;
		}
		drop(server_output);
		thread::sleep(Duration::from_millis(100));

		if start.elapsed() > Duration::from_secs(30) {
			panic!("Server failed to start");
		}
	}

	thread::sleep(Duration::from_secs(1));
	println!("Server started!!!!!!!");

	// Create an HTTP client
	let client = Client::new();

	// Log in to get tokens
	let admin_token = login(&client, "admin", &admin_login_key).await.unwrap();
	let user_token = login(&client, "user", &user_login_key).await.unwrap();

	// Test APIs
	let red_png = hex::decode("89504e470d0a1a0a0000000d494844520000000a0000000a08060000008d32cfbd0000001849444154789c63fccfc0f09f8108c0448ca25185d45308003d9c0212b60323d50000000049454e44ae426082").unwrap();
	let blue_png = hex::decode("89504e470d0a1a0a0000000d494844520000000a0000000a08060000008d32cfbd0000001849444154789c636460f8ff9f8108c0448ca25185d45308003b9e02120bc3baab0000000049454e44ae426082").unwrap();
	let image1_hash = create_test_image(&temp_dir.path().join("images"), "test image 1".as_bytes());
	let image2_hash = create_test_image(&temp_dir.path().join("images"), &red_png);

	// Add data needed later
	call_api(&client, &admin_token, "tags/testtag2", Method::POST, None, StatusCode::CREATED).await;
	call_api(
		&client,
		&admin_token,
		&format!("images/{}", image2_hash),
		Method::POST,
		None,
		StatusCode::CREATED,
	)
	.await;

	test_api(
		&client,
		&admin_token,
		&user_token,
		"tags/testtag",
		Method::POST,
		None,
		"tags/testtag",
		Method::POST,
		None,
		"post/tags",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"tags/testtag",
		Method::DELETE,
		None,
		"tags/testtag",
		Method::DELETE,
		None,
		"delete/tags",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		&format!("images/{}", image1_hash),
		Method::POST,
		None,
		&format!("images/{}", image1_hash),
		Method::POST,
		None,
		"post/images",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		&format!("images/{}", image1_hash),
		Method::DELETE,
		None,
		&format!("images/{}", image1_hash),
		Method::DELETE,
		None,
		"delete/images",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"images/0/tags/0",
		Method::POST,
		None,
		"images/0/tags/0",
		Method::POST,
		None,
		"post/images/tags",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"images/0/tags/0",
		Method::DELETE,
		None,
		"images/0/tags/0",
		Method::DELETE,
		None,
		"delete/images/tags",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"images/0/attributes/source/land/false",
		Method::POST,
		None,
		"images/0/attributes/source/land/false",
		Method::POST,
		None,
		"post/images/attributes",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"images/0/attributes/source/land",
		Method::DELETE,
		None,
		"images/0/attributes/source/land",
		Method::DELETE,
		None,
		"delete/images/attributes",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"users/1",
		Method::GET,
		None,
		"users/1",
		Method::GET,
		None,
		"get/users/1",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"users",
		Method::GET,
		None,
		"users",
		Method::GET,
		None,
		"get/users",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"users/1/tokens",
		Method::GET,
		None,
		"users/1/tokens",
		Method::GET,
		None,
		"get/users/1/tokens",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"users/1/scopes",
		Method::POST,
		Some(&json!({"new_scopes": "post/users/1/scopes"})),
		"users/1/scopes",
		Method::POST,
		Some(&json!({"new_scopes": "post/users/1/scopes"})),
		"post/users/1/scopes",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"images/0/imgops",
		Method::POST,
		None,
		"images/0/imgops",
		Method::POST,
		None,
		"post/images/imgops",
	)
	.await; // TODO
	test_api(
		&client,
		&admin_token,
		&user_token,
		"images/0/predict/tags",
		Method::GET,
		None,
		"images/0/predict/tags",
		Method::GET,
		None,
		"get/images/predict/tags",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"images/0/predict/caption?prompt=test",
		Method::GET,
		None,
		"images/0/predict/caption?prompt=test",
		Method::GET,
		None,
		"get/images/predict/caption",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"task-queue",
		Method::POST,
		Some(&json!({"group": "test", "data": "{}", "status": "waiting"})),
		"task-queue",
		Method::POST,
		Some(&json!({"group": "test", "data": "{}", "status": "waiting"})),
		"post/task-queue",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"task-queue/1",
		Method::DELETE,
		None,
		"task-queue/1",
		Method::DELETE,
		None,
		"delete/task-queue",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"task-queue",
		Method::GET,
		None,
		"task-queue",
		Method::GET,
		None,
		"get/task-queue",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"task-queue",
		Method::POST,
		Some(&json!({"group": "test", "data": "{}", "status": "waiting"})),
		"task-queue",
		Method::POST,
		Some(&json!({"group": "test", "data": "{}", "status": "waiting"})),
		"post/task-queue",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"task-queue/test/acquire",
		Method::POST,
		None,
		"task-queue/test/acquire",
		Method::POST,
		None,
		"post/task-queue/acquire",
	)
	.await;
	test_api(
		&client,
		&admin_token,
		&user_token,
		"task-queue/1/finish",
		Method::POST,
		None,
		"task-queue/1/finish",
		Method::POST,
		None,
		"post/task-queue/acquire",
	)
	.await;
	//test_upload(&client, admin_token, user_token, &blue_png).await;  // TODO: Server has trouble creating temporary files in temporary directories...

	// Change login key
	let user_login_key2: [u8; 32] = thread_rng().gen(); // OsRng not needed for testing
	test_api(
		&client,
		&admin_token,
		&user_token,
		"users/1/login_key",
		Method::POST,
		Some(&json!({"new_login_key": hex::encode(&user_login_key2)})),
		"users/1/login_key",
		Method::POST,
		Some(&json!({"new_login_key": hex::encode(&user_login_key2)})),
		"post/users/1/login_key",
	)
	.await;

	// Make sure only new login key works
	set_user_scopes(&client, &admin_token, "post/users/1/tokens").await;
	assert!(login(&client, "user", &user_login_key).await.is_none());
	let user_token2 = login(&client, "user", &LoginKey(user_login_key2)).await.unwrap();

	// Invalidate old token and make sure it no longer works
	test_api(
		&client,
		&admin_token,
		&user_token2,
		"users/me/tokens/invalidate",
		Method::POST,
		Some(&json!({"token": &user_token})),
		"users/me/tokens/invalidate",
		Method::POST,
		Some(&json!({"token": &user_token2})),
		"delete/users/1/tokens",
	)
	.await;
	set_user_scopes(&client, &admin_token, "get/users/1").await;
	call_api(&client, &user_token, "users/1", Method::GET, None, StatusCode::UNAUTHORIZED).await;
	call_api(&client, &user_token2, "users/1", Method::GET, None, StatusCode::OK).await;

	// Check APIs that don't require scope, but require a logged in user
	call_api(&client, &user_token2, "tags", Method::GET, None, StatusCode::OK).await;
	call_api(&client, &user_token2, "tag_mappings", Method::GET, None, StatusCode::OK).await;
	call_api(&client, &user_token2, "images/0/metadata", Method::GET, None, StatusCode::OK).await;
	call_api(&client, &user_token2, "images/0", Method::GET, None, StatusCode::OK).await;
	call_api(&client, &user_token2, "search/images?query=id=0&select=id", Method::GET, None, StatusCode::OK).await;

	call_api(&client, &user_token, "tags", Method::GET, None, StatusCode::UNAUTHORIZED).await;
	call_api(&client, &user_token, "tag_mappings", Method::GET, None, StatusCode::UNAUTHORIZED).await;
	call_api(&client, &user_token, "images/0/metadata", Method::GET, None, StatusCode::UNAUTHORIZED).await;
	call_api(&client, &user_token, "images/0", Method::GET, None, StatusCode::UNAUTHORIZED).await;
	call_api(
		&client,
		&user_token,
		"search/images?query=id=0&select=id",
		Method::GET,
		None,
		StatusCode::UNAUTHORIZED,
	)
	.await;

	// Terminate the server process
	prediction_handle.stop(true).await;
	server_process.kill().await.expect("Failed to kill server process");
	server_process.wait().await.expect("Failed to wait for server process");
}

fn create_test_image(images_dir: &Path, data: &[u8]) -> String {
	let mut hasher = Sha256::new();
	hasher.update(data);
	let hash = hasher.finalize();
	let hash = hex::encode(hash);
	let path = images_dir.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
	std::fs::create_dir_all(path.parent().unwrap()).unwrap();
	std::fs::write(path, data).unwrap();

	hash
}

async fn login(client: &Client, username: &str, login_key: &LoginKey) -> Option<String> {
	let login_response = client
		.post("http://127.0.0.1:7734/login")
		.json(&json!({
			"username": username,
			"login_key": hex::encode(login_key.0),
		}))
		.send()
		.await
		.expect("Failed to send login request");

	if !login_response.status().is_success() {
		return None;
	}

	let login_json: serde_json::Value = login_response.json().await.unwrap();
	let user_token = login_json["token"].as_str().unwrap();

	Some(user_token.to_string())
}

async fn call_api(client: &Client, admin_token: &str, api: &str, method: Method, body: Option<&serde_json::Value>, expected_status: StatusCode) {
	let request = client.request(method, format!("http://127.0.0.1:7734/{}", api)).bearer_auth(admin_token);

	let request = if let Some(body) = body { request.json(body) } else { request };

	let response = request.send().await.expect("Failed to send request");
	assert_eq!(
		response.status(),
		expected_status,
		"Expected {} to return status {}, {}",
		api,
		expected_status,
		response.text().await.unwrap()
	);
}

async fn test_api(
	client: &Client,
	admin_token: &str,
	user_token: &str,
	positive_api: &str,
	positive_method: Method,
	positive_body: Option<&serde_json::Value>,
	negative_api: &str,
	negative_method: Method,
	negative_body: Option<&serde_json::Value>,
	scope: &str,
) {
	// Set user's scopes
	set_user_scopes(client, admin_token, scope).await;

	// Positive test: Should succeed
	let request = client
		.request(positive_method, format!("http://127.0.0.1:7734/{}", positive_api))
		.bearer_auth(user_token);

	let request = if let Some(body) = positive_body { request.json(body) } else { request };

	let response = request.send().await.unwrap();
	assert!(
		response.status().is_success(),
		"Expected {} to succeed: {}",
		positive_api,
		response.text().await.unwrap()
	);

	// Negative test: Should fail
	set_user_scopes(client, admin_token, "").await;

	let request = client
		.request(negative_method, format!("http://127.0.0.1:7734/{}", negative_api))
		.bearer_auth(user_token);
	let request = if let Some(body) = negative_body { request.json(body) } else { request };
	let response = request.send().await.unwrap();
	assert_eq!(response.status(), StatusCode::FORBIDDEN, "Expected {} to be forbidden", negative_api);
}

async fn test_upload(client: &Client, admin_token: &str, user_token: &str, data: &[u8]) {
	// Positive test: Should succeed
	let file_part = reqwest::multipart::Part::bytes(Vec::from(data)).file_name("file");
	let form = reqwest::multipart::Form::new().part("file", file_part);
	set_user_scopes(client, admin_token, "post/upload_image").await;
	let response = client
		.post(format!("http://127.0.0.1:7734/upload_image"))
		.multipart(form)
		.bearer_auth(user_token)
		.send()
		.await
		.unwrap();
	assert!(response.status().is_success(), "Failed to upload image: {}", response.text().await.unwrap());

	// Negative test: Should fail
	let file_part = reqwest::multipart::Part::bytes(Vec::from(data)).file_name("file");
	let form = reqwest::multipart::Form::new().part("file", file_part);
	set_user_scopes(client, admin_token, "").await;
	let response = client
		.post(format!("http://127.0.0.1:7734/upload_image"))
		.multipart(form)
		.bearer_auth(user_token)
		.send()
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::FORBIDDEN, "Expected upload to be forbidden");
}

// Helper function to set user scopes
async fn set_user_scopes(client: &Client, user_token: &str, scopes: &str) {
	let response = client
		.post("http://127.0.0.1:7734/users/1/scopes")
		.bearer_auth(user_token)
		.json(&json!({
			"new_scopes": scopes,
		}))
		.send()
		.await
		.expect("Failed to send change scopes request");

	assert!(response.status().is_success(), "Failed to set user scopes, status: {}", response.status());
}

async fn create_server() -> (tokio::process::Child, LoginKey, LoginKey, tempfile::TempDir, ServerHandle) {
	let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");

	// Write server secrets
	let secrets_path = temp_dir.path().join("secrets.json");
	let server_secret: [u8; 32] = thread_rng().gen(); // OsRng not needed for testing
	std::fs::write(
		&secrets_path,
		&serde_json::to_vec(&json!({
			"server_secret": hex::encode(server_secret),
		}))
		.unwrap(),
	)
	.expect("Failed to write server secrets");

	let (admin_login_key, user_login_key) = {
		let database = Database::open(temp_dir.path(), true).await.expect("Failed to open database");
		let admin_scopes = "post/users/*/scopes, get/users/*, */images/tags, */images/attributes, post/images/imgops, post/upload_image, post/users/*/tokens, */tags, */images";
		let admin_login_key: [u8; 32] = thread_rng().gen(); // OsRng not needed for testing
		let admin_login_key = LoginKey(admin_login_key);
		let admin_hashed_login_key = admin_login_key.hash();
		database
			.add_user("admin".to_string(), admin_hashed_login_key, admin_scopes.to_string())
			.await
			.expect("Failed to add admin user");

		let user_login_key: [u8; 32] = thread_rng().gen(); // OsRng not needed for testing
		let user_login_key = LoginKey(user_login_key);
		let user_hashed_login_key = user_login_key.hash();
		database
			.add_user("user".to_string(), user_hashed_login_key, "post/users/1/tokens".to_string())
			.await
			.expect("Failed to add user");

		(admin_login_key, user_login_key)
	};

	let server_process = Command::new(env!("CARGO_BIN_EXE_server"))
		.arg("--server-ip")
		.arg("127.0.0.1")
		.arg("--server-port")
		.arg("7734")
		.arg("--prediction-server")
		.arg("http://127.0.0.1:9184")
		.arg("--db-dir")
		.arg(temp_dir.path())
		.arg("--secrets-path")
		.arg(secrets_path)
		.arg("--image-dir")
		.arg(temp_dir.path().join("images"))
		.arg("--upload-dir")
		.arg(temp_dir.path().join("upload"))
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true)
		.spawn()
		.expect("Failed to start server process");

	// Need a fake prediction server
	let prediction_server = HttpServer::new(move || {
		actix_web::App::new()
			.service(actix_web::web::resource("/predict").to(|| async { actix_web::HttpResponse::Ok().json(vec!["tag1", "tag2", "tag3"]) }))
			.service(actix_web::web::resource("/tag_assoc").to(|| async { actix_web::HttpResponse::Ok().json(vec!["tag1", "tag2", "tag3"]) }))
			.service(actix_web::web::resource("/caption").to(|| async { actix_web::HttpResponse::Ok().json("A test caption") }))
	})
	.workers(1)
	.bind(("127.0.0.1", 9184))
	.expect("Failed to bind prediction server")
	.run();

	let prediction_handle = prediction_server.handle();

	tokio::spawn(async move {
		prediction_server.await.expect("Prediction server failed");
	});

	(server_process, admin_login_key, user_login_key, temp_dir, prediction_handle)
}
