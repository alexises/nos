//! The router. Show and transaction-root operations are registered together
//! with their `#[utoipa::path]` docs (`routes!`), so the spec and the router
//! can't disagree; the wildcard config-tree routes are documented by
//! `openapi::document`. Swagger UI is served at `/swagger-ui/`.

use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::{Config, SwaggerUi};

use crate::auth::{basic_auth, BasicAuthScheme};
use crate::ipc::Daemons;
use crate::{clear, openapi, show, tx};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "NOS REST API",
        description = "Every `show` query and the transaction/config editing surface of the NOS \
            shell. Every request needs HTTP Basic credentials of a user in the config \
            (`set user <name> password <clear>`). The config tree is the URL tree — `/v1/transactions/{tx}` is the whole in-progress \
            config and each path below it a subsection; `diff` and `commit` are reserved."
    ),
    modifiers(&BasicAuthScheme),
    security(("basic" = [])),
    tags(
        (name = "show", description = "Read-only operational state"),
        (name = "transactions", description = "Named config transactions"),
        (name = "clear", description = "Operator actions on live state (never config)")
    )
)]
struct ApiDoc;

fn openapi_routes() -> (Router<Daemons>, utoipa::openapi::OpenApi) {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(show::config))
        .routes(routes!(show::routes))
        .routes(routes!(show::route_lookup))
        .routes(routes!(show::interfaces))
        .routes(routes!(show::interface))
        .routes(routes!(show::port_aggregates))
        .routes(routes!(show::port_aggregate))
        .routes(routes!(show::lacp))
        .routes(routes!(show::lacp_one))
        .routes(routes!(show::lldp_neighbors))
        .routes(routes!(show::logs))
        .routes(routes!(show::logs_follow))
        .routes(routes!(show::bgp_summary))
        .routes(routes!(show::ospf_neighbors))
        .routes(routes!(show::ospf_database))
        .routes(routes!(show::ospfv3_neighbors))
        .routes(routes!(show::ospfv3_database))
        .routes(routes!(clear::bgp_soft_in))
        // `diff` and `commit` are static routes, so they win over the
        // `{*path}` wildcard below — which makes them reserved first
        // segments (no config section has those names).
        .routes(routes!(tx::diff))
        .routes(routes!(tx::commit))
        .routes(routes!(tx::open, tx::get, tx::put, tx::delete))
        .split_for_parts()
}

/// The full `OpenAPI` document (also what `GET /openapi.json` serves).
pub fn openapi_document() -> Value {
    openapi::document(&openapi_routes().1)
}

pub fn router(daemons: Daemons) -> Router {
    let (router, base) = openapi_routes();
    let doc = Arc::new(openapi::document(&base));
    router
        // The config tree: every path below a transaction is a subsection.
        // The trailing-slash form of the root is the same resource.
        .route(
            "/v1/transactions/{tx}/",
            get(tx::get).post(tx::open).put(tx::put).delete(tx::delete),
        )
        .route(
            "/v1/transactions/{tx}/{*path}",
            get(tx::get).put(tx::put).delete(tx::delete),
        )
        .route(
            "/openapi.json",
            get(move || async move { Json((*doc).clone()) }),
        )
        // Swagger UI reads the route above (not a `utoipa` struct of its own),
        // so it shows the generated config-tree paths too.
        .merge(SwaggerUi::new("/swagger-ui").config(Config::from("/openapi.json")))
        .with_state(daemons.clone())
        // Last, so it wraps every route above — the merged Swagger UI, the
        // OpenAPI document and the SSE log stream included.
        .layer(axum::middleware::from_fn_with_state(daemons, basic_auth))
}
