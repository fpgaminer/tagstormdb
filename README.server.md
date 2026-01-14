# TagStormDB Server

This README covers specifically the server side of TagStormDB.  For the workings of the database itself, see the main [README.md](./README.md).

The server is basically just an API server for tag-machine and handles interacting with the database, user auth, etc.


## APIs

* GET /tag_mappings
* GET /tags
* POST /tags/{name}
		.service(remove_tag)
		.service(get_image)
		.service(get_image_data)
		.service(add_image)
		.service(remove_image)
		.service(add_image_attribute)
		.service(add_image_attribute_json)
		.service(remove_image_attribute)
		.service(remove_image_attribute_json)
		.service(tag_image)
		.service(untag_image)
		.service(login)
		.service(change_login_key)
		.service(user_info)
		.service(invalidate_user_token)
		.service(list_user_tokens)
		.service(change_user_scopes)
		.service(search_images)
		.service(upload_image)
		.service(imgops_upload)
		.service(create_user)
		.service(get_cf_turnstile_key)
		.service(list_users)
		.service(predict_tags)
		.service(predict_caption)
		.service(task_queue_insert)
		.service(task_queue_delete)
		.service(task_queue_view)
		.service(task_queue_acquire)
		.service(task_queue_finish)


## Authentication and Scopes



## GET /tags

Returns a list of all tags in the database.

```json
[
	{
		"id": 1,
		"name": "tag1",
		"active": true
	},
	{
		"id": 2,
		"name": "tag2",
		"active": true
	}
]
```


## GET /tag_mappings

Returns as JSON a bunch of pre-built information about the tags.  Mostly just convience.  Things like aliases, implications, blacklist, deprecations, etc.


## POST /tags/{name}

Adds a tag to the database.


## DELETE /tags/{name}

Removes a tag from the database.  Note that this will remove the tag from all images as well.


## GET /images/{identifier}/metadata

Returns metadata for the image with the given identifier (ID or hash).  If hash, hex encoded.

```json
{
	"id": 1,
	"hash": "abcdef1234567890...",
	"active": true,
	"tags": {
		"3": 8,
		"5": 2
	}
	"attributes": {
		"width": {"1920", 8},
		"height": {"1080", 8}
	}
}
```

For both "tags" and "attributes", they are returned as maps from value to blame user ID (the user who made the most recent change to that value).  For tags the keys are the tag IDs.



## GET /images/{identifier}

Returns the image file for the image with the given identifier (ID or hash).  If hash, hex encoded.


## POST /images/{hash}

Add an image to the database.  It must already exist on disk in the image store.


## DELETE /images/{identifier}



## POST /images/{image}/tags/{tag}

Adds a tag to the image.  Image can be specified with either ID or hash.  Tag can be specified with either ID or name.


## DELETE /images/{image}/tags/{tag}

Removes a tag from the image.  Image can be specified with either ID or hash.  Tag can be specified with either ID or name.


## POST /images/{image}/attributes/{key}/{value}/{singular}

Adds an attribute to the image.  Image can be specified with either ID or hash.  If "singular" is true, the attribute will be treated as singular (only one value allowed).  That means any existing values for that key will be removed first.


## POST /images/{image}/attributes

Adds an attribute to an image via a JSON body.  The body should be of the form:

```json
{
	"key": "attribute_key",
	"value": "attribute_value",
	"singular": true
}
```


## DELETE /images/{image}/attributes/{key}/{value}

Removes an attribute from the image.  Image can be specified with either ID or hash.  Will only remove the specified value for the given key.


## DELETE /images/{image}/attributes

Removes an attribute from an image via a JSON body.  The body should be of the form:

```json
{
	"key": "attribute_key",
	"value": "attribute_value"
}
```


## POST /login


## POST /users/me/tokens/invalidate


## POST /users/{user}/login_key


## GET /users/{user}


## GET /users


## GET /users/{user}/tokens


## POST /users/{user}/scopes


## GET /search/images


## POST /upload_image


## POST /images/{image}/imgops



## POST /users



## GET /cf_turnstile_key



## GET /images/{image}/predict/tags


## GET /images/{image}/predict/caption
