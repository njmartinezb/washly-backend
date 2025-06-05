pub mod auth {
    use std::{
        ops::Add,
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::{
        body::Body,
        extract::Request,
        http::{
            StatusCode,
            header::{AUTHORIZATION, CONTENT_TYPE},
        },
        middleware::Next,
        response::Response,
    };
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
    use scrypt::{
        Scrypt,
        password_hash::{
            PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
        },
    };
    use serde_json::json;
    use sqlx::{query, query_as};

    use crate::model::{
        AppState, Claims, User,
        requests::{LoginRequest, SignUp},
        responses::{ErrorResponse, LoginResponse, SuccessResponse},
    };

    pub async fn get_user(state: &AppState, email: &str) -> Result<Option<User>, ErrorResponse> {
        let existing_user = query_as!(
            User,
            r#"
            SELECT name, salt, password, email, role FROM users
            WHERE email = $1
        "#,
            email
        )
        .fetch_optional(&state.pool)
        .await;

        match existing_user {
            Ok(None) => Ok(None),
            Ok(Some(user)) => Ok(Some(user)),
            Err(e) => Err(ErrorResponse::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string(),
            )),
        }
    }

    pub async fn login(
        state: &AppState,
        log_in: LoginRequest,
    ) -> Result<LoginResponse, ErrorResponse> {
        match get_user(state, &log_in.email).await {
            Ok(None) => Err(ErrorResponse::new(
                StatusCode::FORBIDDEN,
                format!("No user with email {} exists", log_in.email),
            )),
            Ok(Some(user)) => {
                if user.role != log_in.role {
                    return Err(ErrorResponse::new(
                        StatusCode::FORBIDDEN,
                        "The roles don't match in auth request".to_string(),
                    ));
                }

                let salt_string =
                    SaltString::from_b64(&user.salt).expect("Salt stored in db is valid salt");

                let password_hash = Scrypt
                    .hash_password(user.password.as_bytes(), &salt_string)
                    .map_err(|e| ErrorResponse::new(StatusCode::FORBIDDEN, e.to_string()))?
                    .to_string();

                let parsed_hash =
                    PasswordHash::new(&password_hash).expect("Password hash is valid");

                if let Err(e) = Scrypt.verify_password(log_in.password.as_bytes(), &parsed_hash) {
                    return Err(ErrorResponse::new(StatusCode::FORBIDDEN, e.to_string()));
                }

                match encode(
                    &Header::default(),
                    &Claims {
                        sub: user.email,
                        exp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("Date is valid")
                            .as_millis()
                            .add(3600000) as u64,
                        role: user.role,
                        name: user.name,
                    },
                    &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
                ) {
                    Ok(jwt) => Ok(LoginResponse { token: jwt }),
                    Err(e) => Err(ErrorResponse::new(StatusCode::FORBIDDEN, e.to_string())),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn check_for_valid_jwt(request: Request, next: Next) -> Response {
        let headers = request.headers();

        let auth_header = headers.iter().find(|(name, _)| *name == AUTHORIZATION);

        let error_res = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(CONTENT_TYPE, "application/json");

        match auth_header {
            Some((_, value)) => {
                let header_value = value.to_str().expect("Header value couldn't be a str");

                if decode_jwt(header_value).is_ok() {
                    let res = next.run(request).await;
                    return res;
                }

                let body = Body::from(
                    serde_json::to_string(&json!({
                        "message" : "Not a valid authorization header"
                    }))
                    .expect("JSON value is valid"),
                );

                error_res.body(body).expect("Request is valid")
            }
            None => {
                let body = Body::from(
                    serde_json::to_string(&json!({
                        "message" : "No authorization header present"
                    }))
                    .expect("JSON value is valid"),
                );

                error_res.body(body).expect("Request is valid")
            }
        }
    }

    pub fn decode_jwt(token: &str) -> Result<TokenData<Claims>, ErrorResponse> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "exp", "role"]);

        let secret_key = std::env::var("JWT_KEY").expect("JWT_KEY MUST BE SET");

        match decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret_key.as_bytes()),
            &validation,
        ) {
            Ok(c) => Ok(c),
            Err(e) => Err(ErrorResponse::new(
                StatusCode::BAD_REQUEST,
                format!("Failure to decode jwt: {:?}", e.kind()),
            )),
        }
    }

    pub async fn create_user(
        state: &AppState,
        sign_up: SignUp,
    ) -> Result<SuccessResponse<u64>, ErrorResponse> {
        let salt = SaltString::generate(&mut OsRng);

        let hashed_password = Scrypt
            .hash_password(sign_up.password.as_bytes(), &salt)
            .map_err(|e| ErrorResponse::new(StatusCode::BAD_REQUEST, e.to_string()))?
            .to_string();

        let user_creation = query!(
            r#"
            INSERT INTO users(email,password,salt,name, role)
            VALUES ($1,$2,$3,$4,$5)
        "#,
            sign_up.email,
            hashed_password,
            salt.to_string(),
            sign_up.username,
            serde_json::to_string(&sign_up.role).expect("Enum value is serializable")
        )
        .execute(&state.pool)
        .await;

        match user_creation {
            Ok(res) => Ok(SuccessResponse::new(res.rows_affected())),
            Err(e) => Err(ErrorResponse::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.to_string(),
            )),
        }
    }
}

pub mod orders {
    use crate::model::{
        AppState, Order,
        requests::{AssignOrderToUser, CreateOrder, RescheduleOrder},
        responses::ErrorResponse,
    };
    use axum::http::StatusCode;
    use sqlx::{query, query_as, types::time::PrimitiveDateTime};
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    use uuid::Uuid;

    pub async fn find_order(state: &AppState, order_id: Uuid) -> Result<Order, ErrorResponse> {
        let order_query = query_as!(
            Order,
            r#"
            SELECT 
                id,
                created_at,
                full_address,
                latitude as lat,
                longitude as lng,
                modified_at,
                scheduled_for,
                status
            FROM orders
            WHERE id = $1
        "#,
            order_id
        )
        .fetch_one(&state.pool)
        .await
        .map_err(|e| ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(order_query)
    }

    async fn create_reschedule_row(
        state: &AppState,
        curr_order: &Order,
        order_request: &RescheduleOrder,
    ) -> Result<u64, ErrorResponse> {
        let new_date = PrimitiveDateTime::parse(&order_request.new_date, &Rfc3339)
            .map_err(|e| ErrorResponse::new(StatusCode::BAD_REQUEST, e.to_string()))?;

        let res = query!(
            r#"
        INSERT INTO reschedule_history(order_id,old_date,new_date)
        VALUES ($1,$2,$3)
        "#,
            curr_order.id,
            curr_order.scheduled_for,
            new_date,
        )
        .execute(&state.pool)
        .await
        .map_err(|e| ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(res.rows_affected())
    }
    /*
    async fn set_new_date_on_order(
        state: &AppState,
        curr_order: Order,
        order_request: RescheduleOrder,
    ) -> Result<Order, ErrorResponse> {
        let new_date = PrimitiveDateTime::parse(&order_request.new_date, &Rfc3339)
            .map_err(|e| ErrorResponse::new(StatusCode::BAD_REQUEST, e.to_string()))?;
        let now_utc = OffsetDateTime::now_utc();
        let now = PrimitiveDateTime::new(now_utc.date(), now_utc.time());

        let update_res = query_as!(
            Order,
            r#"
            UPDATE orders
            SET modified_at = $1, scheduled_for = $2, status = $3
            WHERE id = $4
            RETURNING
                id,
                created_at,
                full_address,
                latitude as lat,
                longitude as lng,
                modified_at,
                scheduled_for,
                status
        "#,
            now,
            new_date,
            "open",
            curr_order.id
        )
        .fetch_one(&state.pool)
        .await
        .map_err(|e| ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(update_res)
    }
    */
    async fn set_new_date_on_order(
        state: &AppState,
        curr_order: Order,
        order_request: RescheduleOrder,
    ) -> Result<Order, ErrorResponse> {
        let new_date = PrimitiveDateTime::parse(&order_request.new_date, &Rfc3339)
            .map_err(|e| ErrorResponse::new(StatusCode::BAD_REQUEST, e.to_string()))?;
        let now_utc = OffsetDateTime::now_utc();
        let now = PrimitiveDateTime::new(now_utc.date(), now_utc.time());

        let (new_full_address, new_lat, new_lng) = match &order_request.new_location {
            Some(loc) => (
                Some(loc.address.as_str()), // &str so it can map to a TEXT column
                Some(loc.lat),
                Some(loc.lng),
            ),
            None => (None, None, None),
        };

        let update_res = query_as!(
            Order,
            r#"
            UPDATE orders
            SET
                modified_at    = $1,
                scheduled_for  = $2,
                status         = $3,
                full_address   = COALESCE($5, full_address),
                latitude       = COALESCE($6, latitude),
                longitude      = COALESCE($7, longitude)
            WHERE id = $4
            RETURNING
                id,
                created_at,
                full_address,
                latitude  AS lat,
                longitude AS lng,
                modified_at,
                scheduled_for,
                status
            "#,
            now,              // $1
            new_date,         // $2
            "open",           // $3
            curr_order.id,    // $4
            new_full_address, // $5 (Option<&str>)
            new_lat,          // $6 (Option<f64>)
            new_lng           // $7 (Option<f64>)
        )
        .fetch_one(&state.pool)
        .await
        .map_err(|e| ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(update_res)
    }

    pub async fn reschedule_order(
        state: &AppState,
        order_id: Uuid,
        order_request: RescheduleOrder,
    ) -> Result<Order, ErrorResponse> {
        let order_to_modify = find_order(state, order_id).await?;

        create_reschedule_row(state, &order_to_modify, &order_request).await?;
        let new = set_new_date_on_order(state, order_to_modify, order_request).await?;

        Ok(new)
    }

    pub async fn create_order(
        state: &AppState,
        order_request: CreateOrder,
    ) -> Result<Order, ErrorResponse> {
        let date = PrimitiveDateTime::parse(&order_request.scheduled_for, &Rfc3339)
            .map_err(|e| ErrorResponse::new(StatusCode::BAD_REQUEST, e.to_string()))?;

        let order = sqlx::query_as!(
            Order,
            r#"
        INSERT INTO orders (
            full_address,
            latitude,
            longitude,
            scheduled_for,
            status
        )
        VALUES (
            $1,
            $2, 
            $3,
            $4,
            $5
        )
        RETURNING
            id,
            created_at,
            full_address,
            latitude as lat,
            longitude as lng,
            modified_at,
            scheduled_for,
            status
        "#,
            order_request.full_address,
            order_request.lat,
            order_request.lng,
            date,
            "open",
        )
        .fetch_one(&state.pool)
        .await
        .map_err(|e| ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(order)
    }

    pub async fn find_all(state: &AppState) -> Result<Vec<Order>, ErrorResponse> {
        let all_orders = query_as!(
            Order,
            r#"
        SELECT 
            id,
            created_at,
            full_address,
            latitude as lat,
            longitude as lng,
            modified_at,
            scheduled_for,
            status
        FROM orders
        "#
        )
        .fetch_all(&state.pool)
        .await
        .map_err(|e| ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(all_orders)
    }

    pub async fn assign_user_to_order(
        state: &AppState,
        assignment: AssignOrderToUser,
        order_id: Uuid,
    ) -> Result<u64, ErrorResponse> {
        let now_utc = OffsetDateTime::now_utc();
        let now = PrimitiveDateTime::new(now_utc.date(), now_utc.time());

        let assign_req = query!(
            r#"
            UPDATE orders
            SET modified_at = $1, assigned_to = $2
            WHERE id = $3
        "#,
            now,
            assignment.user_id,
            order_id
        )
        .execute(&state.pool)
        .await
        .map_err(|e| ErrorResponse::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(assign_req.rows_affected())
    }
}
