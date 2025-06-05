use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::PrimitiveDateTime;
use uuid::Uuid;

pub mod requests {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Deserialize, Serialize)]
    pub enum SignUpRoles {
        #[serde(rename = "service")]
        Service,
        #[serde(rename = "user")]
        User,
    }

    #[derive(Deserialize)]
    pub struct AssignOrderToUser {
        pub user_id: Uuid,
    }

    #[derive(Deserialize)]
    pub struct SignUp {
        pub email: String,
        pub password: String,
        pub username: String,
        pub role: SignUpRoles,
    }

    #[derive(Deserialize)]
    pub struct LoginRequest {
        pub email: String,
        pub password: String,
        pub role: String,
    }

    #[derive(Deserialize)]
    pub struct LocationUpdate {
        pub address: String,
        pub lat: f64,
        pub lng: f64,
    }

    #[derive(Deserialize)]
    pub struct RescheduleOrder {
        pub new_date: String,
        pub new_location: Option<LocationUpdate>,
    }

    #[derive(Deserialize)]
    pub struct CreateOrder {
        pub full_address: String,
        pub lat: f64,
        pub lng: f64,
        pub scheduled_for: String,
    }
}

pub struct Config {
    pub jwt_secret: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub name: String,
    pub exp: u64,
    pub role: String,
}

pub struct User {
    pub email: String,
    pub name: String,
    pub salt: String,
    pub role: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct Order {
    pub id: Uuid,
    pub created_at: PrimitiveDateTime,
    pub full_address: String,
    pub lat: f64,
    pub lng: f64,
    pub modified_at: Option<PrimitiveDateTime>,
    pub scheduled_for: PrimitiveDateTime,
    pub status: String,
}

pub mod responses {
    use axum::http::StatusCode;
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct ErrorResponse {
        #[serde(skip)]
        pub status: StatusCode,
        pub message: String,
    }

    #[derive(Serialize)]
    pub struct SuccessResponse<T: Serialize> {
        data: T,
    }

    impl<T: Serialize> SuccessResponse<T> {
        pub fn new(data: T) -> Self {
            SuccessResponse { data }
        }
    }

    impl ErrorResponse {
        pub fn new(status: StatusCode, message: String) -> Self {
            ErrorResponse { message, status }
        }
    }

    #[derive(Serialize)]
    pub struct LoginResponse {
        pub token: String,
    }
}
