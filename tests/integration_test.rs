use futures::future::join_all;
use ordered_float::NotNan;
use std::{collections::HashSet, sync::Arc};
use tagstormdb::{
	database::{ImageEntry, StateUpdateResult},
	AttributeKeyId, HashedLoginKey, UserToken,
};
use tempfile::TempDir;

use tagstormdb::{AttributeValueId, Database, ImageHash, ImageId, TagId, UserId};

#[tokio::test(flavor = "multi_thread")]
async fn test_database_operations() {
	// Create a temporary directory for the database files
	let temp_dir = TempDir::new().expect("Failed to create temp dir");

	// Initialize the database
	let db_path = temp_dir.path();
	println!("Database path: {:?}", db_path);
	let db = Database::open(db_path, false).await.unwrap();
	println!("Database initialized");

	// === Test adding tags ===
	let user_id = UserId(1);
	let tag_names = vec!["tag1", "tag2", "tag3"];

	for tag_name in &tag_names {
		let result = db.add_tag(tag_name.to_string(), user_id).await.unwrap();
		assert!(result, "Tag '{}' should be added", tag_name);
	}

	// Attempt to add duplicate tags
	for tag_name in &tag_names {
		let result = db.add_tag(tag_name.to_string(), user_id).await.unwrap();
		assert!(!result, "Duplicate tag '{}' should not be added", tag_name);
	}

	// Check that the tags are in the database
	{
		let tags = db.tags.read().await;
		for (i, tag_name) in tag_names.iter().enumerate() {
			let tag_id = db.get_tag_id(tag_name).await.expect("Tag ID should exist");
			assert_eq!(tag_id, TagId(i as u64), "Tag ID should match");
			let tag_entry = tags.get_by_id(tag_id).expect("Tag entry should exist");
			assert!(tag_entry.active, "Tag '{}' should be active", tag_name);
		}
	}

	// Remove a tag
	let tag_to_remove = "tag2";
	let tag_id = db.get_tag_id(tag_to_remove).await.expect("Tag ID should exist");
	let result = db.remove_tag(tag_id, user_id).await.unwrap();
	assert!(result, "Tag '{}' should be removed", tag_to_remove);

	// Attempt to remove the same tag again
	let result = db.remove_tag(tag_id, user_id).await.unwrap();
	assert!(!result, "Removing the same tag '{}' again should return false", tag_to_remove);

	// Attempt to remove a non-existent tag
	let non_existent_tag_id = TagId(999);
	let result = db.remove_tag(non_existent_tag_id, user_id).await.unwrap();
	assert!(!result, "Removing a non-existent tag should return false");

	// === Test adding images ===
	let image_hashes: Vec<ImageHash> = vec![ImageHash([1u8; 32]), ImageHash([2u8; 32]), ImageHash([3u8; 32])];

	for image_hash in &image_hashes {
		let result = db.add_image(image_hash.clone(), user_id).await.unwrap();
		assert!(result, "Image should be added");
	}

	// Attempt to add duplicate images
	for image_hash in &image_hashes {
		let result = db.add_image(image_hash.clone(), user_id).await.unwrap();
		assert!(!result, "Duplicate image should not be added");
	}

	// Check that the images are in the database
	{
		let images = db.images.read().await;
		for (i, image_hash) in image_hashes.iter().enumerate() {
			let image_entry = images.get_by_key(image_hash).expect("Image should exist");
			assert_eq!(image_entry.id, ImageId(i as u64), "Image ID should match");
			assert!(image_entry.active, "Image should be active");
		}
	}

	// Remove an image
	let image_to_remove = db.get_image_id(&image_hashes[1]).await.expect("Image should exist");
	let result = db.remove_image(image_to_remove, user_id).await.unwrap();
	assert!(result, "Image should be removed");

	// Attempt to remove the same image again
	let result = db.remove_image(image_to_remove, user_id).await.unwrap();
	assert!(!result, "Removing the same image again should return false");

	// Attempt to remove a non-existent image
	let non_existent_image_id = ImageId(999);
	let result = db.remove_image(non_existent_image_id, user_id).await.unwrap();
	assert!(!result, "Removing a non-existent image should return false");

	// === Test adding tags to images ===
	// Re-add the removed tag and image
	let tag_id = db.get_tag_id(tag_to_remove).await.expect("Tag ID should exist");
	let result = db.add_tag(tag_to_remove.to_string(), user_id).await.unwrap();
	assert!(result, "Tag should be re-added");

	let image_hash = image_hashes[1];
	let result = db.add_image(image_hash.clone(), user_id).await.unwrap();
	assert!(result, "Image should be re-added");

	let image_id = db.images.read().await.get_by_key(&image_hash).expect("Image should exist").id;

	// Add tag to image
	let result = db.add_image_tag(image_id, tag_id, user_id).await.unwrap();
	assert_eq!(result, StateUpdateResult::Updated(()), "Tag should be added to image");

	// Attempt to add the same tag to the image again
	let result = db.add_image_tag(image_id, tag_id, user_id).await.unwrap();
	assert_eq!(result, StateUpdateResult::NoOp, "Adding the same tag to image again should return false");

	// Check that the image has the tag
	let images = db.images.read().await;
	let image_entry = images.get_by_id(image_id).expect("Image should exist");
	let image_id = image_entry.id;
	assert!(image_entry.tags.contains_key(&tag_id), "Image should have the tag");
	drop(images);

	// Remove tag from image
	let result = db.remove_image_tag(image_id, tag_id, user_id).await.unwrap();
	assert_eq!(result, StateUpdateResult::Updated(()), "Tag should be removed from image");

	// Attempt to remove the tag from the image again
	let result = db.remove_image_tag(image_id, tag_id, user_id).await.unwrap();
	assert_eq!(result, StateUpdateResult::NoOp, "Removing the same tag from image again should be a no-op");

	// Attempt to remove a tag that the image doesn't have
	let non_existent_tag_id = TagId(999);
	let result = db.remove_image_tag(image_id, non_existent_tag_id, user_id).await.unwrap();
	assert_eq!(result, StateUpdateResult::NoOp, "Removing a non-existent tag from image should be a no-op");

	// Remove the tag and image again
	assert!(db.remove_tag(tag_id, user_id).await.unwrap(), "Tag should be removed");

	// === Test adding attributes to images ===
	let attribute_key = "size".to_string();
	let attribute_values = vec!["small".to_string(), "medium".to_string(), "large".to_string()];

	for (i, attribute_value) in attribute_values.iter().enumerate() {
		let result = db
			.add_image_attribute(ImageId(i as u64), attribute_key.clone(), attribute_value.clone(), user_id)
			.await
			.unwrap();
		assert_eq!(result, StateUpdateResult::Updated(()), "Attribute should be added to image");

		// Attempt to add the same attribute again
		let result = db
			.add_image_attribute(ImageId(i as u64), attribute_key.clone(), attribute_value.clone(), user_id)
			.await
			.unwrap();
		assert_eq!(result, StateUpdateResult::NoOp, "Adding the same attribute to image again should be a no-op");
	}

	// Check that the attributes are in the images
	let images = db.images.read().await;
	for (i, attribute_value) in attribute_values.iter().enumerate() {
		let image_entry = images.get_by_id(ImageId(i as u64)).expect("Image should exist");
		let key_id = db.get_string_id(&attribute_key).await.expect("Key ID should exist").into();
		let value_id = db.get_string_id(attribute_value).await.expect("Value ID should exist").into();

		assert!(image_entry.attributes.contains_key(&key_id), "Image should have the attribute key");
		let values = image_entry.attributes.get(&key_id).unwrap();
		assert!(values.contains_key(&value_id), "Image should have the attribute value");
	}
	drop(images);

	// Remove an attribute from an image
	let image_id = ImageId(0);
	let key_id = db.get_string_id(&attribute_key).await.expect("Key ID should exist").into();
	let value_id = db.get_string_id(&attribute_values[0]).await.expect("Value ID should exist").into();

	let result = db.remove_image_attribute(image_id, key_id, value_id, user_id).await.unwrap();
	assert_eq!(result, StateUpdateResult::Updated(()), "Attribute should be removed from image");

	// Attempt to remove the attribute again
	let result = db.remove_image_attribute(image_id, key_id, value_id, user_id).await.unwrap();
	assert_eq!(
		result,
		StateUpdateResult::NoOp,
		"Removing the same attribute from image again should be a no-op"
	);

	// Attempt to remove an attribute that the image doesn't have
	let non_existent_value_id = AttributeValueId(999);
	let result = db.remove_image_attribute(image_id, key_id, non_existent_value_id, user_id).await.unwrap();
	assert_eq!(
		result,
		StateUpdateResult::NoOp,
		"Removing a non-existent attribute from image should be a no-op"
	);

	// === Test numeric attributes ===
	// Add numeric attributes
	let numeric_attribute_key = "score".to_string();
	let numeric_attribute_values = vec!["1.0".to_string(), "2.5".to_string(), "3.7".to_string()];

	for (i, attribute_value) in numeric_attribute_values.iter().enumerate() {
		let result = db
			.add_image_attribute(ImageId(i as u64), numeric_attribute_key.clone(), attribute_value.clone(), user_id)
			.await
			.unwrap();
		assert_eq!(result, StateUpdateResult::Updated(()), "Numeric attribute should be added to image");
	}

	// Check that the numeric attribute index is updated
	let index_by_attribute_numeric = db.index_by_attribute_numeric.read().await;
	let key_id = db.get_string_id(&numeric_attribute_key).await.expect("Key ID should exist").into();
	let numeric_index = index_by_attribute_numeric.get_by_key(key_id).expect("Numeric index should exist");

	let expected_values: HashSet<_> = numeric_attribute_values
		.iter()
		.map(|s| NotNan::new(s.parse::<f32>().unwrap()).unwrap())
		.collect();

	let actual_values: HashSet<_> = numeric_index.keys().cloned().collect();

	assert_eq!(expected_values, actual_values, "Numeric attribute values should match");
	drop(index_by_attribute_numeric);

	// === Test database persistence ===
	// Close the database (drop the instance)
	drop(db);

	// Re-open the database
	let db = Database::open(db_path, false).await.unwrap();

	// Check that the tags are restored
	let tags = db.tags.read().await;
	for (_, tag_name) in tag_names.iter().enumerate() {
		let tag_id = db.get_tag_id(tag_name).await.expect("Tag ID should exist");
		let tag_entry = tags.get_by_id(tag_id).expect("Tag entry should exist");
		let expected_active = tag_name != &"tag2";
		assert_eq!(tag_entry.active, expected_active, "Tag '{}' active state should match", tag_name);
	}

	// Check that the images are restored
	let images = db.images.read().await;
	for (_, image_hash) in image_hashes.iter().enumerate() {
		let image_entry = images.get_by_key(image_hash).expect("Image should exist");
		let expected_active = true;
		assert_eq!(image_entry.active, expected_active, "Image active state should match");
	}

	// Check that the image tags are restored
	// For the re-added image, the tag was added and then removed
	let image_entry = images.get_by_key(&image_hashes[1]).expect("Image should exist");
	assert!(image_entry.tags.is_empty(), "Image should have no tags");

	// Check that the attributes are restored
	for (i, attribute_value) in attribute_values.iter().enumerate() {
		let image_entry = images.get_by_id(ImageId(i as u64)).expect("Image should exist");
		let key_id = db.get_string_id(&attribute_key).await.expect("Key ID should exist").into();
		let value_id = db.get_string_id(attribute_value).await.expect("Value ID should exist").into();

		let expected_has_attribute = !(i == 0 && attribute_value == &attribute_values[0]);
		if expected_has_attribute {
			assert!(image_entry.attributes.contains_key(&key_id), "Image should have the attribute key");
			let values = image_entry.attributes.get(&key_id).unwrap();
			assert!(values.contains_key(&value_id), "Image should have the attribute value");
		} else {
			assert!(!image_entry.attributes.contains_key(&key_id), "Image should not have the attribute key");
		}
	}
}


enum TestAction {
	AddTag(&'static str),
	RemoveTag(&'static str),
	AddImage(ImageHash),
	RemoveImage(ImageHash),
	AddImageTag(ImageHash, &'static str),
	RemoveImageTag(ImageHash, &'static str),
	AddAttribute(ImageHash, &'static str, &'static str),
	RemoveAttribute(ImageHash, &'static str, &'static str),
}

impl TestAction {
	async fn run(self, db: &Database) {
		match self {
			Self::AddTag(tag_name) => {
				db.add_tag(tag_name.to_string(), UserId(1)).await.unwrap();
			},
			Self::RemoveTag(tag_name) => {
				let tag_id = db.get_tag_id(tag_name).await.expect("Tag ID should exist");
				db.remove_tag(tag_id, UserId(1)).await.unwrap();
			},
			Self::AddImage(image_hash) => {
				db.add_image(image_hash, UserId(1)).await.unwrap();
			},
			Self::RemoveImage(image_hash) => {
				let image_id = db.get_image_id(&image_hash).await.expect("Image ID should exist");
				db.remove_image(image_id, UserId(1)).await.unwrap();
			},
			Self::AddImageTag(image_hash, tag_name) => {
				let image_id = db.get_image_id(&image_hash).await.expect("Image ID should exist");
				let tag_id = db.get_tag_id(tag_name).await.expect("Tag ID should exist");
				assert_eq!(db.add_image_tag(image_id, tag_id, UserId(1)).await.unwrap(), StateUpdateResult::Updated(()));
			},
			Self::RemoveImageTag(image_hash, tag_name) => {
				let image_id = db.get_image_id(&image_hash).await.expect("Image ID should exist");
				let tag_id = db.get_tag_id(tag_name).await.expect("Tag ID should exist");
				assert_eq!(db.remove_image_tag(image_id, tag_id, UserId(1)).await.unwrap(), StateUpdateResult::Updated(()));
			},
			Self::AddAttribute(image_hash, key, value) => {
				let image_id = db.get_image_id(&image_hash).await.expect("Image ID should exist");
				assert_eq!(
					db.add_image_attribute(image_id, key.to_string(), value.to_string(), UserId(1)).await.unwrap(),
					StateUpdateResult::Updated(())
				);
			},
			Self::RemoveAttribute(image_hash, key, value) => {
				let image_id = db.get_image_id(&image_hash).await.expect("Image ID should exist");
				let key_id = db.get_string_id(key).await.expect("Key ID should exist").into();
				let value_id = db.get_string_id(value).await.expect("Value ID should exist").into();
				assert_eq!(
					db.remove_image_attribute(image_id, key_id, value_id, UserId(1)).await.unwrap(),
					StateUpdateResult::Updated(())
				);
			},
		}
	}
}


struct ExpectedState {
	tags: Vec<&'static str>,
	images: Vec<(ImageHash, ExpectedImageState)>,
}

impl ExpectedState {
	async fn check(&self, db: &Database) {
		let tags = db.tags.read().await;
		let db_tags: HashSet<_> = tags
			.iter()
			.filter_map(|(tag_name, tag)| if tag.active { Some(tag_name.to_string()) } else { None })
			.collect();
		let expected_tags: HashSet<_> = self.tags.iter().map(|s| s.to_string()).collect();

		assert_eq!(db_tags, expected_tags, "Tags should match");

		let images = db.images.read().await;
		let db_hashes = images
			.iter()
			.filter_map(|(hash, image)| if image.active { Some(hash) } else { None })
			.collect::<HashSet<_>>();
		let expected_hashes = self.images.iter().map(|(hash, _)| hash).collect::<HashSet<_>>();

		assert_eq!(db_hashes, expected_hashes, "Images should match");

		for (hash, expected_image) in &self.images {
			let db_image = images.get_by_key(hash).expect("Image should exist");
			expected_image.check(db_image, db).await;
		}
	}
}

struct ExpectedImageState {
	tags: Vec<&'static str>,
	attributes: Vec<(&'static str, &'static str)>,
}

impl ExpectedImageState {
	async fn check(&self, db_image: &ImageEntry, db: &Database) {
		for tag_name in &self.tags {
			let tag_id = db.get_tag_id(tag_name).await.expect("Tag ID should exist");
			assert!(db_image.tags.contains_key(&tag_id), "Image should have tag '{}'", tag_name);
		}

		let db_attributes: HashSet<_> = db_image
			.attributes
			.iter()
			.flat_map(|(key_id, values)| values.iter().map(move |(value_id, _)| (*key_id, *value_id)))
			.collect();

		let mut expected_attributes = HashSet::new();

		for (key, value) in &self.attributes {
			let key_id: AttributeKeyId = db.get_string_id(key).await.expect("Key ID should exist").into();
			let value_id: AttributeValueId = db.get_string_id(value).await.expect("Value ID should exist").into();
			expected_attributes.insert((key_id, value_id));
		}

		assert_eq!(db_attributes, expected_attributes, "Image attributes should match");
	}
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tag_remove_affects_images() {
	// Test that removing a tag removes it from all images
	let actions = [
		TestAction::AddTag("tag1"),
		TestAction::AddTag("tag2"),
		TestAction::AddTag("tag3"),
		TestAction::AddImage(ImageHash([1u8; 32])),
		TestAction::AddImageTag(ImageHash([1u8; 32]), "tag1"),
		TestAction::AddImageTag(ImageHash([1u8; 32]), "tag2"),
		TestAction::AddImageTag(ImageHash([1u8; 32]), "tag3"),
		TestAction::RemoveTag("tag2"),
	];

	let expected = ExpectedState {
		tags: vec!["tag1", "tag3"],
		images: vec![(
			ImageHash([1u8; 32]),
			ExpectedImageState {
				tags: vec!["tag1", "tag3"],
				attributes: vec![],
			},
		)],
	};

	let temp_dir = TempDir::new().expect("Failed to create temp dir");
	let db_path = temp_dir.path();
	let db = Database::open(db_path, false).await.unwrap();

	for action in actions {
		action.run(&db).await;
	}

	// Verify state is as expected
	expected.check(&db).await;
}


#[tokio::test(flavor = "multi_thread")]
async fn test_user_management() {
	// Setup temporary database directory
	let temp_dir = TempDir::new().expect("Failed to create temp dir");
	let db_path = temp_dir.path();
	let db = Database::open(db_path, false).await.unwrap();

	// === Test user creation ===
	let username = "user1";
	let hashed_login_key = HashedLoginKey([0; 32]); // Example login key
	let scopes = "read,write";
	let user_id = db.add_user(username.to_string(), hashed_login_key, scopes.to_string()).await.unwrap();

	// Verify that user ID is assigned correctly
	{
		assert!(db.get_user_by_id(user_id, &db.users.read().await).is_some(), "User should be created");
	}

	// === Test duplicate user creation ===
	let duplicate_result = db.add_user(username.to_string(), hashed_login_key, scopes.to_string()).await;
	assert!(duplicate_result.is_err(), "Duplicate user creation should fail");

	// === Test creating a user token ===
	let token = db.create_user_token(user_id).await.unwrap();
	let tokens = db.list_user_tokens_by_user_id(user_id).await;
	assert!(tokens.contains(&token), "User token should be created and associated with the user");

	// === Test invalidating user token ===
	db.invalidate_user_token(&token).await.unwrap();
	let tokens_after_invalidation = db.list_user_tokens_by_user_id(user_id).await;
	assert!(!tokens_after_invalidation.contains(&token), "User token should be invalidated");

	// === Test login authentication ===
	let auth_result = db.authenticate_login(username, hashed_login_key).await.unwrap();
	assert_eq!(auth_result, Some(user_id), "User should authenticate successfully");

	// Test invalid login with wrong key
	let wrong_key = HashedLoginKey([1; 32]); // Different key
	let wrong_auth_result = db.authenticate_login(username, wrong_key).await.unwrap();
	assert_eq!(wrong_auth_result, None, "Authentication with wrong key should fail");

	// === Test updating scopes ===
	let new_scopes = "read,write,admin";
	db.change_user_scopes(user_id, new_scopes.to_string()).await.unwrap();

	{
		let users_read = db.users.read().await;
		let (_, user_entry) = db.get_user_by_id(user_id, &users_read).expect("User should exist");
		assert_eq!(user_entry.scopes, new_scopes, "User scopes should be updated");
	}

	// === Test updating login key ===
	db.change_user_login_key(user_id, wrong_key).await.unwrap();
	println!("DEBUG 11");
	let updated_auth_result = db.authenticate_login(username, wrong_key).await.unwrap();
	assert_eq!(updated_auth_result, Some(user_id), "User should authenticate with new login key");
}


#[tokio::test(flavor = "multi_thread")]
async fn test_user_token_management() {
	// Setup temporary database directory
	let temp_dir = TempDir::new().expect("Failed to create temp dir");
	let db_path = temp_dir.path();
	let db = Database::open(db_path, false).await.unwrap();

	// === Test creating and validating multiple tokens for a single user ===
	let username = "user2";
	let hashed_login_key = HashedLoginKey([2; 32]);
	let scopes = "read";
	let user_id = db.add_user(username.to_string(), hashed_login_key, scopes.to_string()).await.unwrap();

	// Create multiple tokens
	let token1 = db.create_user_token(user_id).await.unwrap();
	let token2 = db.create_user_token(user_id).await.unwrap();
	let tokens = db.list_user_tokens_by_user_id(user_id).await;

	assert!(tokens.contains(&token1), "User should have token1");
	assert!(tokens.contains(&token2), "User should have token2");

	// === Test invalidating one token ===
	db.invalidate_user_token(&token1).await.unwrap();
	let tokens_after_invalidation = db.list_user_tokens_by_user_id(user_id).await;
	assert!(!tokens_after_invalidation.contains(&token1), "Token1 should be invalidated");
	assert!(tokens_after_invalidation.contains(&token2), "Token2 should still be valid");

	// === Test invalidating all tokens ===
	db.invalidate_user_token(&token2).await.unwrap();
	let tokens_after_all_invalidation = db.list_user_tokens_by_user_id(user_id).await;
	assert!(tokens_after_all_invalidation.is_empty(), "All tokens should be invalidated");
}


#[tokio::test(flavor = "multi_thread")]
async fn test_token_invalidation_for_nonexistent_token() {
	let temp_dir = TempDir::new().expect("Failed to create temp dir");
	let db_path = temp_dir.path();
	let db = Database::open(db_path, false).await.unwrap();

	// Attempt to invalidate a non-existent token
	let non_existent_token = UserToken([0; 32]);
	let result = db.invalidate_user_token(&non_existent_token).await;
	assert!(result.is_ok(), "Invalidating a non-existent token should succeed but have no effect");
}


#[tokio::test(flavor = "multi_thread")]
async fn test_token_creation_for_nonexistent_user() {
	let temp_dir = TempDir::new().expect("Failed to create temp dir");
	let db_path = temp_dir.path();
	let db = Database::open(db_path, false).await.unwrap();

	// Attempt to create a token for a non-existent user
	let non_existent_user_id = UserId(999);
	let result = db.create_user_token(non_existent_user_id).await;
	assert!(result.is_err(), "Creating a token for a non-existent user should fail");
}


#[tokio::test(flavor = "multi_thread")]
async fn test_user_persistence_across_sessions() {
	let temp_dir = TempDir::new().expect("Failed to create temp dir");
	let db_path = temp_dir.path();

	let db = Database::open(db_path, false).await.unwrap();
	let username = "persistent_user";
	let hashed_login_key = HashedLoginKey([3; 32]);
	let scopes = "read,write";
	let user_id = db.add_user(username.to_string(), hashed_login_key, scopes.to_string()).await.unwrap();

	// Create a token and drop the db instance
	let token = db.create_user_token(user_id).await.unwrap();
	drop(db);

	// Reopen the database and check if user and token persist
	let db = Database::open(db_path, false).await.unwrap();
	let user_exists = db.get_user_by_id(user_id, &db.users.read().await).is_some();
	assert!(user_exists, "User should persist across sessions");

	assert_eq!(
		db.get_user_id_by_token(&token).await.expect("Token should exist"),
		user_id,
		"Token should persist across sessions"
	);
}


#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_user_modifications() {
	let temp_dir = TempDir::new().expect("Failed to create temp dir");
	let db_path = temp_dir.path();
	let db = Arc::new(Database::open(db_path, false).await.unwrap());

	// === Create user for concurrent modifications ===
	let username = "concurrent_user";
	let hashed_login_key = HashedLoginKey([4; 32]);
	let scopes = "read,write";
	let user_id = db.add_user(username.to_string(), hashed_login_key, scopes.to_string()).await.unwrap();

	// === Concurrently generate tokens for the same user ===
	let mut token_generation_tasks = Vec::new();
	for _ in 0..10 {
		let db_ref = db.clone();
		let user_id_ref = user_id;
		token_generation_tasks.push(tokio::spawn(async move { db_ref.create_user_token(user_id_ref).await.unwrap() }));
	}

	// Run all token generation tasks and collect the results
	let tokens = join_all(token_generation_tasks)
		.await
		.into_iter()
		.map(|result| result.unwrap()) // Unwrap the JoinHandle result
		.collect::<Vec<_>>();

	// Verify that all tokens are unique and associated with the user
	let unique_tokens: HashSet<_> = tokens.iter().cloned().collect();
	assert_eq!(unique_tokens.len(), tokens.len(), "All generated tokens should be unique");

	let user_tokens = db.list_user_tokens_by_user_id(user_id).await;
	for token in &tokens {
		assert!(user_tokens.contains(token), "Generated token should be associated with the user");
	}

	// === Concurrently invalidate some tokens while generating new ones ===
	let mut token_invalidation_tasks = Vec::new();
	for token in tokens.iter().take(5) {
		let db_ref = db.clone();
		let token_ref = *token;
		token_invalidation_tasks.push(tokio::spawn(async move {
			db_ref.invalidate_user_token(&token_ref).await.unwrap();
			None
		}));
	}

	for _ in 0..5 {
		let db_ref = db.clone();
		let user_id_ref = user_id;
		token_invalidation_tasks.push(tokio::spawn(async move { Some(db_ref.create_user_token(user_id_ref).await.unwrap()) }));
	}

	// Run invalidation and additional generation tasks concurrently
	let new_tokens = join_all(token_invalidation_tasks)
		.await
		.into_iter()
		.filter_map(|result| result.unwrap()) // Unwrap the JoinHandle result
		.collect::<Vec<_>>();

	// Verify that the invalidated tokens are no longer associated with the user
	let user_tokens_after_invalidation = db.list_user_tokens_by_user_id(user_id).await;
	for token in tokens.iter().take(5) {
		assert!(
			!user_tokens_after_invalidation.contains(token),
			"Invalidated token should not be associated with the user"
		);
	}

	// Verify that there are new tokens associated with the user
	for token in new_tokens {
		assert!(
			user_tokens_after_invalidation.contains(&token),
			"Newly generated token should be associated with the user"
		);
	}
}
