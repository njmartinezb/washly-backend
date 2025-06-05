use axum::{
    Router,
    body::Body,
    http::{StatusCode, header::CONTENT_TYPE},
    middleware,
    response::Response,
};
use serde::Serialize;

use crate::{
    model::{AppState, responses::ErrorResponse},
    service::auth::check_for_valid_jwt,
};

fn format_response<T: Serialize>(data: T, status: StatusCode) -> Response<Body> {
    let serialized = serde_json::to_vec(&data).expect("Data type is serializable");
    let body = Body::from(serialized);

    Response::builder()
        .header(CONTENT_TYPE, "application/json")
        .status(status)
        .body(body)
        .expect("Response is valid response")
}

fn format_response_res<T: Serialize>(
    data: Result<T, ErrorResponse>,
    success_status: StatusCode,
) -> Response<Body> {
    let (serialized, status) = match data {
        Ok(data) => (
            serde_json::to_vec(&data).expect("Data type is serializable"),
            success_status,
        ),
        Err(e) => (
            serde_json::to_vec(&e).expect("Data type is serializable"),
            e.status,
        ),
    };

    let body = Body::from(serialized);

    Response::builder()
        .header(CONTENT_TYPE, "application/json")
        .status(status)
        .body(body)
        .expect("Response is valid response")
}

pub mod orders {
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::StatusCode,
        response::IntoResponse,
        routing::{get, patch, post},
    };
    use uuid::Uuid;

    use crate::{
        model::{
            AppState,
            requests::{AssignOrderToUser, CreateOrder, RescheduleOrder},
        },
        service::orders::{
            assign_user_to_order, create_order, find_all, find_order, reschedule_order,
        },
    };

    use super::format_response_res;

    async fn find_by_id(
        State(state): State<AppState>,
        Path(order_id): Path<Uuid>,
    ) -> impl IntoResponse {
        format_response_res(find_order(&state, order_id).await, StatusCode::OK)
    }

    async fn reschedule(
        State(state): State<AppState>,
        Path(order_id): Path<Uuid>,
        Json(reschedule_request): Json<RescheduleOrder>,
    ) -> impl IntoResponse {
        format_response_res(
            reschedule_order(&state, order_id, reschedule_request).await,
            StatusCode::OK,
        )
    }

    async fn get_all(State(state): State<AppState>) -> impl IntoResponse {
        format_response_res(find_all(&state).await, StatusCode::OK)
    }

    async fn assign(
        State(state): State<AppState>,
        Path(order_id): Path<Uuid>,
        Json(assignment): Json<AssignOrderToUser>,
    ) -> impl IntoResponse {
        format_response_res(
            assign_user_to_order(&state, assignment, order_id).await,
            StatusCode::OK,
        )
    }

    async fn create(
        State(state): State<AppState>,
        Json(create_order_dto): Json<CreateOrder>,
    ) -> impl IntoResponse {
        format_response_res(
            create_order(&state, create_order_dto).await,
            StatusCode::CREATED,
        )
    }

    pub fn get_router(state: AppState) -> Router {
        Router::new()
            .route("/", post(create))
            .route("/", get(get_all))
            .route("/{order_id}", get(find_by_id))
            .route("/reschedule/{order_id}", patch(reschedule))
            .route("/assign/{order_id}", patch(assign))
            .with_state(state)
    }
}

pub mod auth {
    use axum::{
        Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post,
    };

    use crate::{
        model::{
            AppState,
            requests::{LoginRequest, SignUp},
            responses::ErrorResponse,
        },
        service::{
            self,
            auth::{create_user, get_user},
        },
    };

    use super::{format_response, format_response_res};

    async fn sign_up(
        State(state): State<AppState>,
        Json(sign_up): Json<SignUp>,
    ) -> impl IntoResponse {
        match get_user(&state, &sign_up.email).await {
            Ok(None) => {
                format_response_res(create_user(&state, sign_up).await, StatusCode::CREATED)
            }
            Ok(Some(user)) => format_response_res(
                Err::<(), ErrorResponse>(ErrorResponse::new(
                    StatusCode::CONFLICT,
                    format!("User with email {} already exists", user.email),
                )),
                StatusCode::OK,
            ),
            Err(e) => format_response(e, StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    pub async fn login(
        State(state): State<AppState>,
        Json(login_req): Json<LoginRequest>,
    ) -> impl IntoResponse {
        format_response_res(
            service::auth::login(&state, login_req).await,
            StatusCode::OK,
        )
    }

    pub fn get_router(state: AppState) -> Router {
        Router::new()
            .route("/sign_up", post(sign_up))
            .route("/login", post(login))
            .with_state(state)
    }
}

pub fn get_router(state: AppState) -> Router {
    Router::new()
        .nest("/orders", orders::get_router(state.clone()))
        .layer(middleware::from_fn(check_for_valid_jwt))
        .nest("/auth", auth::get_router(state))
}
