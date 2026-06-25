use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use worker::Env;

use crate::handlers::{
    accounts, admin, attachments, auth_requests, ciphers, config, devices, domains, duo,
    emergency_access, events, folders, identity, import, key_connector, meta, organizations, scim,
    sends, sso, sync, twofactor, webauth,
};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        // Key Connector (SSO key retrieval)
        .route(
            "/api/key-connector/keys",
            get(key_connector::get_keys).post(key_connector::store_keys),
        )
        .route("/api/users/{id}/keys", get(key_connector::get_user_keys))
        // SCIM 2.0 (directory sync) — org-scoped, API-key auth
        .route(
            "/scim/v2/{org_id}/Users",
            get(scim::list_users).post(scim::create_user),
        )
        .route(
            "/scim/v2/{org_id}/Users/{id}",
            get(scim::get_user)
                .put(scim::replace_user)
                .patch(scim::patch_user)
                .delete(scim::delete_user),
        )
        .route(
            "/scim/v2/{org_id}/Groups",
            get(scim::list_groups).post(scim::create_group),
        )
        .route("/scim/v2/{org_id}/Groups/{id}", delete(scim::delete_group))
        // Admin panel (gated by ADMIN_TOKEN secret)
        .route("/admin", get(admin::admin_page))
        .route("/admin/api/login", post(admin::admin_login))
        .route("/admin/api/stats", get(admin::admin_stats))
        .route("/admin/api/users", get(admin::admin_list_users))
        .route(
            "/admin/api/users/{id}/delete",
            post(admin::admin_delete_user),
        )
        .route(
            "/admin/api/users/{id}/verify-email",
            post(admin::admin_verify_email),
        )
        .route("/admin/api/config", get(admin::admin_config))
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/prelogin/password",
            post(accounts::prelogin),
        )
        .route("/identity/accounts/register", post(accounts::register))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        // SSO (OIDC) login flow
        .route("/identity/connect/authorize", get(sso::authorize))
        .route("/identity/connect/oidc-signin", get(sso::oidc_signin))
        .route("/identity/connect/sso-tenants", get(sso::list_sso_tenants))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        // Email verification (consume token)
        .route("/api/accounts/verify-email", post(accounts::verify_email))
        .route(
            "/api/accounts/send-verification-email",
            post(accounts::send_verification_email_authed),
        )
        // Main data sync route
        .route("/api/sync", get(sync::get_sync_data))
        // For on-demand sync checks
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        .route("/api/accounts/password-hint", post(accounts::password_hint))
        .route("/api/tasks", get(accounts::get_tasks))
        .route("/api/accounts/profile", get(accounts::get_profile))
        .route("/api/accounts/profile", post(accounts::post_profile))
        .route("/api/accounts/profile", put(accounts::put_profile))
        .route("/api/accounts/avatar", put(accounts::put_avatar))
        // Delete account
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        // Set KDF
        .route("/api/accounts/kdf", post(accounts::post_kdf))
        // Change password
        .route("/api/accounts/password", post(accounts::post_password))
        // Log out all sessions via security stamp rotation
        .route("/api/accounts/security-stamp", post(accounts::post_sstamp))
        // Rotate encryption keys
        .route(
            "/api/accounts/key-management/rotate-user-account-keys",
            post(accounts::post_rotatekey),
        )
        // Auth requests (login with device)
        .route(
            "/api/auth-requests",
            get(auth_requests::get_auth_requests).post(auth_requests::post_auth_request),
        )
        .route(
            "/api/auth-requests/pending",
            get(auth_requests::get_auth_requests_pending),
        )
        .route(
            "/api/auth-requests/{id}/response",
            get(auth_requests::get_auth_request_response),
        )
        .route(
            "/api/auth-requests/{id}",
            get(auth_requests::get_auth_request).put(auth_requests::put_auth_request),
        )
        // Ciphers CRUD
        .route("/api/ciphers", get(ciphers::list_ciphers))
        .route("/api/ciphers", post(ciphers::create_cipher_simple))
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route("/api/ciphers/import", post(import::import_data))
        .route("/api/ciphers/{id}", get(ciphers::get_cipher))
        .route(
            "/api/ciphers/{id}/details",
            get(ciphers::get_cipher_details),
        )
        // Attachments
        .route(
            "/api/ciphers/{id}/attachment/v2",
            post(attachments::create_attachment_v2),
        )
        // Note: Azure upload/download routes are intercepted in handlers::streaming (zero-copy)
        // PUT /api/ciphers/{id}/attachment/{attachment_id}/azure-upload
        // GET /api/ciphers/{id}/attachment/{attachment_id}/download?token=...
        .route(
            "/api/ciphers/{id}/attachment",
            post(attachments::upload_attachment_legacy),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            post(attachments::upload_attachment_v2_data),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            get(attachments::get_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}",
            delete(attachments::delete_attachment),
        )
        .route(
            "/api/ciphers/{id}/attachment/{attachment_id}/delete",
            post(attachments::delete_attachment_post),
        )
        .route("/api/ciphers/{id}", put(ciphers::update_cipher))
        .route("/api/ciphers/{id}", post(ciphers::update_cipher))
        // Cipher soft delete (PUT sets deleted_at timestamp)
        .route("/api/ciphers/{id}/delete", put(ciphers::soft_delete_cipher))
        // Cipher hard delete (DELETE/POST permanently removes cipher)
        .route("/api/ciphers/{id}", delete(ciphers::hard_delete_cipher))
        .route(
            "/api/ciphers/{id}/delete",
            post(ciphers::hard_delete_cipher),
        )
        // Partial update for folder/favorite
        .route(
            "/api/ciphers/{id}/partial",
            put(ciphers::update_cipher_partial),
        )
        .route(
            "/api/ciphers/{id}/partial",
            post(ciphers::update_cipher_partial),
        )
        // Cipher bulk soft delete
        .route(
            "/api/ciphers/delete",
            put(ciphers::soft_delete_ciphers_bulk),
        )
        // Cipher bulk hard delete
        .route(
            "/api/ciphers/delete",
            post(ciphers::hard_delete_ciphers_bulk),
        )
        .route("/api/ciphers", delete(ciphers::hard_delete_ciphers_bulk))
        // Cipher restore (clears deleted_at)
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        // Cipher bulk restore
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers_bulk))
        // Cipher archive (sets archived_at)
        .route("/api/ciphers/{id}/archive", put(ciphers::archive_cipher))
        .route(
            "/api/ciphers/{id}/unarchive",
            put(ciphers::unarchive_cipher),
        )
        // Cipher bulk archive
        .route("/api/ciphers/archive", put(ciphers::archive_ciphers_bulk))
        .route(
            "/api/ciphers/unarchive",
            put(ciphers::unarchive_ciphers_bulk),
        )
        // Move ciphers to folder
        .route("/api/ciphers/move", post(ciphers::move_cipher_selected))
        .route("/api/ciphers/move", put(ciphers::move_cipher_selected))
        // Share a personal cipher into an organization
        .route("/api/ciphers/{id}/share", put(ciphers::share_cipher))
        // Purge vault - delete all ciphers and folders (requires password verification)
        .route("/api/ciphers/purge", post(ciphers::purge_vault))
        // Folders CRUD
        .route("/api/folders", get(folders::list_folders))
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", get(folders::get_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/folders/{id}/delete", post(folders::delete_folder))
        // Sends
        .route("/api/sends", get(sends::list_sends))
        .route("/api/sends", post(sends::create_text_send))
        .route("/api/sends/file/v2", post(sends::create_file_send_v2))
        .route("/api/sends/file", post(sends::create_file_send_legacy))
        .route(
            "/api/sends/{send_id}/file/{file_id}",
            post(sends::upload_file_send_direct),
        )
        .route("/api/sends/{send_id}", get(sends::get_send))
        .route("/api/sends/{send_id}", put(sends::update_send))
        .route("/api/sends/{send_id}", delete(sends::delete_send))
        .route(
            "/api/sends/{send_id}/remove-password",
            put(sends::remove_password),
        )
        // Send anonymous access (no auth required)
        .route("/api/sends/access/{access_id}", post(sends::access_send))
        .route(
            "/api/sends/{send_id}/access/file/{file_id}",
            post(sends::access_file_send),
        )
        .route("/api/config", get(config::config))
        // Meta endpoints (mirrors a subset of vaultwarden core/mod.rs)
        .route("/api/alive", get(meta::alive))
        .route("/api/now", get(meta::now))
        .route("/api/version", get(meta::version))
        .route("/api/hibp/breach", get(meta::hibp_breach))
        // Settings (stubbed)
        .route("/api/settings/domains", get(domains::get_domains))
        .route("/api/settings/domains", post(domains::post_domains))
        .route("/api/settings/domains", put(domains::put_domains))
        // Emergency access (full lifecycle: invite/accept/confirm/initiate/approve/reject/view/takeover)
        .route(
            "/api/emergency-access/trusted",
            get(emergency_access::get_trusted_contacts),
        )
        .route(
            "/api/emergency-access/granted",
            get(emergency_access::get_granted_access),
        )
        .route(
            "/api/emergency-access/invite",
            post(emergency_access::send_invite),
        )
        .route(
            "/api/emergency-access/{id}",
            get(emergency_access::get_emergency_access)
                .put(emergency_access::put_emergency_access)
                .post(emergency_access::post_emergency_access)
                .delete(emergency_access::delete_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/delete",
            post(emergency_access::post_delete_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/reinvite",
            post(emergency_access::resend_invite),
        )
        .route(
            "/api/emergency-access/{id}/accept",
            post(emergency_access::accept_invite),
        )
        .route(
            "/api/emergency-access/{id}/confirm",
            post(emergency_access::confirm_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/initiate",
            post(emergency_access::initiate_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/approve",
            post(emergency_access::approve_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/reject",
            post(emergency_access::reject_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/view",
            post(emergency_access::view_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/takeover",
            post(emergency_access::takeover_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/password",
            post(emergency_access::password_emergency_access),
        )
        .route(
            "/api/emergency-access/{id}/policies",
            get(emergency_access::policies_emergency_access),
        )
        // Devices (stub - device tracking not implemented, JWT-based auth)
        .route("/api/devices", get(devices::get_devices))
        .route("/api/devices/knowndevice", get(devices::get_known_device))
        .route(
            "/api/devices/identifier/{device_id}",
            get(devices::get_device),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            post(devices::post_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            put(devices::put_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            put(devices::put_clear_device_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            post(devices::post_clear_device_token),
        )
        // WebAuthn (passkey) 2FA
        .route(
            "/api/webauthn",
            get(webauth::get_webauthn_credentials).post(webauth::post_webauthn_challenge),
        )
        .route(
            "/api/webauthn/complete",
            post(webauth::complete_webauthn_register),
        )
        .route("/api/webauthn", delete(webauth::delete_webauthn_credential))
        // Two-factor authentication
        .route("/api/two-factor", get(twofactor::get_twofactor))
        .route(
            "/api/two-factor/get-authenticator",
            post(twofactor::get_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            post(twofactor::activate_authenticator),
        )
        .route(
            "/api/two-factor/authenticator",
            put(twofactor::activate_authenticator_put),
        )
        .route(
            "/api/two-factor/authenticator",
            delete(twofactor::disable_authenticator),
        )
        .route(
            "/api/two-factor/disable",
            post(twofactor::disable_twofactor),
        )
        .route(
            "/api/two-factor/disable",
            put(twofactor::disable_twofactor_put),
        )
        .route("/api/two-factor/get-recover", post(twofactor::get_recover))
        .route("/api/two-factor/recover", post(twofactor::recover))
        // Yubikey 2FA
        .route("/api/two-factor/get-yubikey", post(twofactor::get_yubikey))
        .route("/api/two-factor/yubikey", post(twofactor::activate_yubikey))
        .route("/api/two-factor/yubikey", put(twofactor::activate_yubikey))
        // Email 2FA
        .route("/api/two-factor/get-email", post(twofactor::get_email))
        .route(
            "/api/two-factor/send-email",
            post(twofactor::send_email_2fa),
        )
        .route("/api/two-factor/email", post(twofactor::activate_email))
        .route("/api/two-factor/email", put(twofactor::activate_email))
        // Duo 2FA
        .route("/api/two-factor/get-duo", post(duo::get_duo))
        .route("/api/two-factor/duo", post(duo::activate_duo))
        .route("/api/two-factor/duo", put(duo::activate_duo))
        // Protected-action OTP request
        .route("/api/accounts/otp", post(accounts::request_otp))
        // Organizations & sharing
        .route(
            "/api/organizations",
            post(organizations::create_organization),
        )
        .route(
            "/api/organizations/{id}",
            get(organizations::get_organization).delete(organizations::delete_organization),
        )
        .route(
            "/api/organizations/{id}/leave",
            post(organizations::leave_organization),
        )
        .route(
            "/api/organizations/{id}/users",
            get(organizations::list_users),
        )
        .route(
            "/api/organizations/{id}/users/invite",
            post(organizations::invite_users),
        )
        .route(
            "/api/organizations/{org_id}/users/{id}/accept",
            post(organizations::accept_user),
        )
        .route(
            "/api/organizations/{org_id}/users/{id}/confirm",
            post(organizations::confirm_user),
        )
        .route(
            "/api/organizations/{org_id}/users/{id}",
            put(organizations::update_user).delete(organizations::remove_user),
        )
        .route(
            "/api/organizations/{id}/collections",
            get(organizations::list_collections).post(organizations::create_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{id}",
            put(organizations::update_collection).delete(organizations::delete_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{id}/users",
            get(organizations::list_collection_users),
        )
        .route(
            "/api/organizations/{id}/policies",
            get(organizations::list_policies),
        )
        .route(
            "/api/organizations/{org_id}/policies/{policy_type}",
            get(organizations::get_policy).put(organizations::update_policy),
        )
        .route(
            "/api/organizations/{id}/groups",
            get(organizations::list_groups).post(organizations::create_group),
        )
        .route(
            "/api/organizations/{id}/delete",
            post(organizations::post_delete_organization),
        )
        .route(
            "/api/organizations/{id}/import",
            post(organizations::import),
        )
        // Event log (org audit trail)
        .route(
            "/api/organizations/{id}/events",
            get(events::list_org_events),
        )
        .with_state(app_state)
}
