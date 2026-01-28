use actix_web::{web, App, HttpServer, HttpResponse, Result, HttpRequest, middleware, cookie::Cookie};
use actix_files::Files;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    url: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

struct AppState {
    config: Arc<Mutex<Config>>,
}

fn check_auth_cookie(req: &HttpRequest) -> bool {
    let expected_password = env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "changeme123".to_string());
    
    if let Some(cookie) = req.cookie("admin_auth") {
        let token = format!("valid_{}", expected_password);
        return cookie.value() == token;
    }
    false
}

async fn admin_login(
    login: web::Json<LoginRequest>,
) -> Result<HttpResponse> {
    let expected_password = env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "changeme123".to_string());
    
    if login.password == expected_password {
        let token = format!("valid_{}", expected_password);
        let cookie = Cookie::build("admin_auth", token)
            .path("/")
            .max_age(actix_web::cookie::time::Duration::hours(24))
            .http_only(true)
            .finish();
        
        Ok(HttpResponse::Ok()
            .cookie(cookie)
            .json(serde_json::json!({"success": true})))
    } else {
        Ok(HttpResponse::Unauthorized()
            .json(serde_json::json!({"success": false, "error": "Invalid password"})))
    }
}

async fn admin_logout() -> Result<HttpResponse> {
    let cookie = Cookie::build("admin_auth", "")
        .path("/")
        .max_age(actix_web::cookie::time::Duration::seconds(0))
        .finish();
    
    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({"success": true})))
}

async fn serve_admin(req: HttpRequest) -> Result<HttpResponse> {
    if !check_auth_cookie(&req) {
        let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0a;--surface:#111;--border:#222;--text:#fff;--text-dim:#888;--accent:#3b82f6;--accent-hover:#2563eb;--error:#ef4444}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-container{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:40px;width:100%;max-width:400px;box-shadow:0 4px 24px rgba(0,0,0,0.5)}
.login-header{text-align:center;margin-bottom:32px}
.login-header h1{font-size:24px;font-weight:600;margin-bottom:8px}
.login-header p{color:var(--text-dim);font-size:14px}
.field{margin-bottom:20px}
.label{display:block;font-size:13px;font-weight:500;margin-bottom:8px;color:var(--text-dim)}
.input{width:100%;padding:12px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;font-family:inherit;transition:all 0.2s}
.input:focus{outline:none;border-color:var(--accent)}
.btn{width:100%;padding:12px;border:none;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;transition:all 0.2s;font-family:inherit;background:var(--accent);color:white}
.btn:hover{background:var(--accent-hover)}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.error{color:var(--error);font-size:13px;margin-top:12px;text-align:center;display:none}
.error.show{display:block}
</style>
</head>
<body>
<div class="login-container">
<div class="login-header">
<h1> Admin Login</h1>
<p>Enter password to continue</p>
</div>
<form id="loginForm">
<div class="field">
<label class="label">Password</label>
<input type="password" class="input" id="password" placeholder="Enter admin password" autofocus required>
</div>
<button type="submit" class="btn">Login</button>
<div class="error" id="error">Invalid password</div>
</form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit',async(e)=>{
e.preventDefault();
const password=document.getElementById('password').value;
const btn=e.target.querySelector('.btn');
const error=document.getElementById('error');
error.classList.remove('show');
btn.disabled=true;
btn.textContent='Logging in...';
try{
const res=await fetch('/api/login',{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({password})
});
const data=await res.json();
if(data.success){
window.location.reload();
}else{
error.classList.add('show');
btn.disabled=false;
btn.textContent='Login';
document.getElementById('password').value='';
document.getElementById('password').focus();
}
}catch(e){
error.textContent='Connection error';
error.classList.add('show');
btn.disabled=false;
btn.textContent='Login';
}
});
</script>
</body>
</html>"#;
        return Ok(HttpResponse::Ok().content_type("text/html").body(html));
    }
    
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0a0a0a;--surface:#111;--border:#222;--text:#fff;--text-dim:#888;--accent:#3b82f6;--accent-hover:#2563eb;--success:#10b981;--danger:#ef4444}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.5;padding:20px}
.container{max-width:800px;margin:0 auto}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;padding-bottom:20px;border-bottom:1px solid var(--border)}
.header h1{font-size:24px;font-weight:600}
.logout-btn{padding:8px 16px;background:var(--danger);color:white;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:500}
.logout-btn:hover{opacity:0.9}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px}
.field{margin-bottom:20px}
.label{display:block;font-size:13px;font-weight:500;margin-bottom:8px;color:var(--text-dim)}
.input{width:100%;padding:12px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;font-family:inherit}
.input:focus{outline:none;border-color:var(--accent)}
.btn{padding:12px 24px;border:none;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;background:var(--accent);color:white}
.btn:hover{background:var(--accent-hover)}
.btn:disabled{opacity:0.5;cursor:not-allowed}
.status{margin-top:16px;padding:12px;border-radius:8px;font-size:14px;display:none}
.status.success{background:rgba(16,185,129,0.1);color:var(--success);border:1px solid rgba(16,185,129,0.2)}
.status.error{background:rgba(239,68,68,0.1);color:var(--danger);border:1px solid rgba(239,68,68,0.2)}
.current-url{margin-bottom:20px;padding:12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;font-size:13px;color:var(--text-dim);word-break:break-all}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>Admin</h1>
<button class="logout-btn" onclick="logout()">Logout</button>
</div>
<div class="panel">
<div class="current-url">Current: <span id="currentUrl">Loading...</span></div>
<form id="urlForm">
<div class="field">
<label class="label">Website URL</label>
<input type="url" class="input" id="url" placeholder="https://example.com" required>
</div>
<button type="submit" class="btn">Update Display</button>
</form>
<div class="status" id="status"></div>
</div>
</div>
<script>
async function loadConfig(){
const res=await fetch('/api/config');
const config=await res.json();
document.getElementById('currentUrl').textContent=config.url;
document.getElementById('url').value=config.url;
}
loadConfig();
document.getElementById('urlForm').addEventListener('submit',async(e)=>{
e.preventDefault();
const url=document.getElementById('url').value;
const btn=e.target.querySelector('.btn');
const status=document.getElementById('status');
btn.disabled=true;
btn.textContent='Updating...';
status.style.display='none';
try{
const res=await fetch('/api/config',{
method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({url,updated_at:new Date().toISOString()})
});
if(res.ok){
status.className='status success';
status.textContent='✓ Display updated successfully!';
status.style.display='block';
document.getElementById('currentUrl').textContent=url;
setTimeout(()=>status.style.display='none',3000);
}else{
throw new Error('Failed');
}
}catch(e){
status.className='status error';
status.textContent='✗ Failed to update display';
status.style.display='block';
}
btn.disabled=false;
btn.textContent='Update Display';
});
async function logout(){
await fetch('/api/logout',{method:'POST'});
window.location.reload();
}
</script>
</body>
</html>"#;
    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

async fn get_config(data: web::Data<AppState>) -> Result<HttpResponse> {
    let config = data.config.lock().unwrap();
    Ok(HttpResponse::Ok().json(&*config))
}

async fn update_config(
    req: HttpRequest,
    data: web::Data<AppState>,
    new_config: web::Json<Config>,
) -> Result<HttpResponse> {
    if !check_auth_cookie(&req) {
        return Ok(HttpResponse::Unauthorized().body("Unauthorized"));
    }
    
    let mut config = data.config.lock().unwrap();
    *config = new_config.into_inner();
    println!("Config updated: {}", config.url);
    Ok(HttpResponse::Ok().json(&*config))
}

async fn serve_display(data: web::Data<AppState>) -> Result<HttpResponse> {
    let config = data.config.lock().unwrap();
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Display</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{width:100%;height:100%;overflow:hidden;background:#000}}
#frame{{width:100%;height:100%;border:none;display:block}}
</style>
</head>
<body>
<iframe id="frame" src="{}"></iframe>
<script>
let lastUpdate='{}';
const frame=document.getElementById('frame');
setInterval(async()=>{{
try{{
const res=await fetch('/api/config');
const config=await res.json();
if(config.updated_at!==lastUpdate){{
lastUpdate=config.updated_at;
const newUrl=config.url+(config.url.includes('?')?'&':'?')+'_t='+Date.now();
frame.src=newUrl;
}}
}}catch(e){{console.error(e)}}
}},1000);
</script>
</body>
</html>"#,
        config.url, config.updated_at
    );
    Ok(HttpResponse::Ok().content_type("text/html").body(html))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    
    let initial_config = Config {
        url: "about:blank".to_string(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    let app_state = web::Data::new(AppState {
        config: Arc::new(Mutex::new(initial_config)),
    });

    println!("Server running on http://0.0.0.0:3000");
    println!("Admin panel: http://localhost:3000/admin");
    println!("Password: {}", env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "changeme123".to_string()));
    
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .route("/", web::get().to(serve_display))
            .route("/admin", web::get().to(serve_admin))
            .route("/api/login", web::post().to(admin_login))
            .route("/api/logout", web::post().to(admin_logout))
            .route("/api/config", web::get().to(get_config))
            .route("/api/config", web::post().to(update_config))
            .service(Files::new("/static", "static"))
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}