// size limits
pub const MAX_PASTE_CONTENT_SIZE: usize = 3_000_000;
pub const MAX_CSS_SIZE: usize = 300_000;
pub const MAX_TOKEN_ATTEMPTS: usize = 3;

pub const MAX_PAGE_TITLE_LEN: usize = 255;
pub const MAX_FAVICON_URL_LEN: usize = 255;
pub const MAX_EMBED_DESCRIPTION_LEN: usize = 255;
pub const MAX_EMBED_IMAGE_URL_LEN: usize = 255;

// reserved tokens and allowed characters in tokens
pub const RESERVED_TOKENS: &[&str] = &[
    "static",
    "edit",
    "save",
    "login",
    "logout",
    "register",
    "profile",
    "dashboard",
];
pub const ALLOWED_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

// pagination
pub const PASTES_PER_PAGE: usize = 10;
pub const FRIENDS_PER_PAGE: u32 = 9;

// paths
pub const SAVE_PASTE_URL: &str = "/save";
pub const EDIT_PASTE_URL_PREFIX: &str = "/edit/";

// dashboard
pub const BASE_COUNT_SQL: &str = "SELECT COUNT(*) FROM pastes WHERE user_id = $1";
pub const BASE_PASTES_SQL: &str =
    "SELECT token, content, css, timestamp, edit_timestamp, user_id FROM pastes WHERE user_id = $1";

pub const SEARCH_COUNT_SQL: &str =
    "SELECT COUNT(*) FROM pastes p WHERE p.user_id = $1 AND p.token LIKE $2";
pub const SEARCH_PASTES_SQL: &str =
    "SELECT p.token, p.content, p.css, p.timestamp, p.edit_timestamp, p.user_id 
                                    FROM pastes p 
                                    WHERE p.user_id = $1 AND p.token LIKE $2";

// template paths
pub const TEMPLATE_PASTE_FORM: &str = "paste/paste_form.html";
pub const TEMPLATE_EDIT_PASTE: &str = "paste/edit_paste.html";
pub const TEMPLATE_PASTE_VIEW: &str = "paste/paste.html";

pub const TEMPLATE_ADMIN_PANEL: &str = "admin/panel.html";
pub const TEMPLATE_ADMIN_PASTES: &str = "admin/pastes.html";
pub const TEMPLATE_ADMIN_USERS: &str = "admin/users.html";

// token generation
pub const TOKEN_LENGTH: usize = 8;

// default profile pictures
pub const DEFAULT_PROFILE_PICTURES: [&str; 6] = [
    "/static/images/default_profile_picture.webp",
    "/static/images/default_profile_picture_1.webp",
    "/static/images/default_profile_picture_2.webp",
    "/static/images/default_profile_picture_3.webp",
    "/static/images/default_profile_picture_4.webp",
    "/static/images/default_profile_picture_5.webp",
];

