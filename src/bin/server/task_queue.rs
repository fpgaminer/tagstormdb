use std::{collections::HashMap, sync::Arc};

use actix_web::{
	web::{self, Data},
	HttpResponse,
};
use rand::seq::SliceRandom;
use serde::Deserialize;
use tagstormdb::{
	database::{TaskEntry, TaskStatus},
	errors::DatabaseError,
	Database,
};

use crate::{
	auth::{AuthenticatedUser, Scope},
	server_error::ServerError,
	TASK_EXPIRATION_TIME,
};


#[derive(Deserialize)]
struct TaskQueueInsertRequest {
	group: String,
	data: String,
	status: TaskStatus,
}

/// Insert a new task into the task queue
#[actix_web::post("/task-queue")]
async fn task_queue_insert(user: AuthenticatedUser, db: Data<Arc<Database>>, req: web::Json<TaskQueueInsertRequest>) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::TaskQueueInsert)?;

	let req = req.into_inner();

	// Verify that data is valid JSON
	match serde_json::from_str::<serde_json::Value>(&req.data) {
		Ok(_) => {},
		Err(e) => return Ok(HttpResponse::BadRequest().body(format!("Invalid JSON: {}", e))),
	}

	db.add_task(req.group, req.data, req.status, user.id).await?;

	Ok(HttpResponse::Created().finish())
}


/// Delete a task from the task queue
#[actix_web::delete("/task-queue/{task_id}")]
async fn task_queue_delete(user: AuthenticatedUser, db: Data<Arc<Database>>, path: web::Path<(u64,)>) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::TaskQueueDelete)?;

	let task_id = path.0;

	match db.remove_task(task_id.into()).await {
		Ok(_) => Ok(HttpResponse::NoContent().finish()),
		Err(DatabaseError::TaskDoesNotExist) => Ok(HttpResponse::NotFound().body("Task not found")),
		Err(e) => Err(ServerError::from(e)),
	}
}


#[derive(Deserialize)]
struct TaskQueueListRequest {
	group: Option<String>,
	count: Option<bool>,
}

/// List tasks in the task queue
#[actix_web::get("/task-queue")]
async fn task_queue_view(user: AuthenticatedUser, db: Data<Arc<Database>>, query: web::Query<TaskQueueListRequest>) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::TaskQueueView)?;

	let task_queue = db.task_queue.read().await;
	let group = match &query.group {
		Some(group) => db.get_string_id(group).await,
		None => None,
	};

	let tasks = task_queue.values().filter_map(|(task, _)| {
		if let Some(group) = &group {
			if task.group == *group {
				Some(task)
			} else {
				None
			}
		} else {
			Some(task)
		}
	});

	if query.count.unwrap_or(false) {
		// Count tasks by status
		let mut counts = HashMap::new();
		let now = chrono::Utc::now().timestamp();

		for task in tasks {
			let status = match task.status {
				TaskStatus::Waiting => TaskStatus::Waiting,
				TaskStatus::InProgress if (now - task.modified_time) > (TASK_EXPIRATION_TIME * 1000) => TaskStatus::Waiting,
				TaskStatus::InProgress => TaskStatus::InProgress,
				TaskStatus::Done => TaskStatus::Done,
			};
			*counts.entry(status).or_insert(0) += 1;
		}

		Ok(HttpResponse::Ok().json(counts))
	} else {
		// List tasks
		let tasks = tasks.map(|task| task.id.0).collect::<Vec<_>>();
		Ok(HttpResponse::Ok().json(tasks))
	}
}


/// Acquire a task from the task queue
#[actix_web::post("/task-queue/{group}/acquire")]
async fn task_queue_acquire(user: AuthenticatedUser, db: Data<Arc<Database>>, path: web::Path<(String,)>) -> Result<HttpResponse, ServerError> {
	// Check permissions
	user.verify_scope(Scope::TaskQueueAcquire)?;

	let (group,) = path.into_inner();
	let group = match db.get_string_id(&group).await {
		Some(group) => group,
		None => return Ok(HttpResponse::NotFound().body("Group not found")),
	};
	let now = chrono::Utc::now().timestamp();

	// Grab a write lock
	let task_queue = db.task_queue.write().await;

	// Find applicable tasks
	let tasks = task_queue
		.values()
		.filter_map(|(task, _)| {
			if task.group == group
				&& (task.status == TaskStatus::Waiting || (task.status == TaskStatus::InProgress && (now - task.modified_time) > (TASK_EXPIRATION_TIME * 1000)))
			{
				Some(task.id)
			} else {
				None
			}
		})
		.collect::<Vec<_>>();

	// Grab a random task
	let task_id = match tasks.choose(&mut rand::thread_rng()) {
		Some(task_id) => *task_id,
		None => return Ok(HttpResponse::NotFound().body("No tasks available")),
	};

	let task = task_queue.get(&task_id).unwrap().0.clone();

	match db
		.update_task(task_id, None, Some(TaskStatus::InProgress), Some(now), Some(user.id), task_queue)
		.await
	{
		Ok(_) => (),
		Err(DatabaseError::TaskDoesNotExist) => return Ok(HttpResponse::Ok().json(None::<Option<TaskEntry>>)),
		Err(e) => return Err(ServerError::from(e)),
	};

	Ok(HttpResponse::Ok().json(task))
}


/// Finish a task from the task queue
#[actix_web::post("/task-queue/{task_id}/finish")]
async fn task_queue_finish(user: AuthenticatedUser, db: Data<Arc<Database>>, path: web::Path<(u64,)>) -> Result<HttpResponse, ServerError> {
	// Check permissions (same permission as acquire)
	user.verify_scope(Scope::TaskQueueAcquire)?;

	let (task_id,) = path.into_inner();
	let now = chrono::Utc::now().timestamp();

	let task_queue = db.task_queue.write().await;

	match db
		.update_task(task_id.into(), None, Some(TaskStatus::Done), Some(now), Some(user.id), task_queue)
		.await
	{
		Ok(_) => Ok(HttpResponse::NoContent().finish()),
		Err(DatabaseError::TaskDoesNotExist) => Ok(HttpResponse::NotFound().body("Task not found")),
		Err(e) => Err(ServerError::from(e)),
	}
}
