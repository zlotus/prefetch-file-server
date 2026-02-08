use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use clap::Parser;
use serde::Deserialize;
use tokio::fs::File as TokioFile;
use tokio::net::TcpListener;
use tokio_util::io::ReaderStream;
use tracing::{info, warn};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
struct FileConfig {
    ip: Option<String>,
    port: Option<u16>,
    token: Option<String>,
    data_dir: Option<String>,
    log_file: Option<String>,
    log_max_size_mb: Option<u64>,
    log_keep_files: Option<usize>,
}

#[derive(Debug, Clone)]
struct AppConfig {
    ip: IpAddr,
    port: u16,
    token: String,
    data_dir: PathBuf,
    log_file: PathBuf,
    log_max_size_bytes: u64,
    log_keep_files: usize,
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    #[arg(long)]
    ip: Option<IpAddr>,

    #[arg(long)]
    port: Option<u16>,

    #[arg(long)]
    token: Option<String>,

    #[arg(long)]
    data_dir: Option<PathBuf>,

    #[arg(long)]
    log_file: Option<PathBuf>,

    #[arg(long)]
    log_max_size_mb: Option<u64>,

    #[arg(long)]
    log_keep_files: Option<usize>,
}

#[derive(Debug, Clone)]
struct AppState {
    token: Arc<str>,
    data_dir: Arc<PathBuf>,
    canonical_data_dir: Arc<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct DownloadQuery {
    token: String,
    filename: String,
}

#[derive(Clone)]
struct RollingFileMakeWriter {
    inner: Arc<Mutex<RollingFileInner>>,
}

struct RollingFileInner {
    base_path: PathBuf,
    file: File,
    current_size: u64,
    max_size: u64,
    keep_files: usize,
}

struct RollingFileWriter {
    inner: Arc<Mutex<RollingFileInner>>,
}

impl RollingFileMakeWriter {
    fn new(base_path: PathBuf, max_size: u64, keep_files: usize) -> Result<Self> {
        if keep_files == 0 {
            return Err(anyhow!("log_keep_files must be >= 1"));
        }

        if let Some(parent) = base_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log dir: {}", parent.display()))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base_path)
            .with_context(|| format!("failed to open log file: {}", base_path.display()))?;

        let current_size = file
            .metadata()
            .with_context(|| format!("failed to stat log file: {}", base_path.display()))?
            .len();

        Ok(Self {
            inner: Arc::new(Mutex::new(RollingFileInner {
                base_path,
                file,
                current_size,
                max_size,
                keep_files,
            })),
        })
    }
}

impl<'a> MakeWriter<'a> for RollingFileMakeWriter {
    type Writer = RollingFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RollingFileWriter {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Write for RollingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "log mutex poisoned"))?;

        if inner.current_size + buf.len() as u64 > inner.max_size {
            rotate_logs(&mut inner)?;
        }

        inner.file.write_all(buf)?;
        inner.current_size += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "log mutex poisoned"))?;
        inner.file.flush()
    }
}

fn rotate_logs(inner: &mut RollingFileInner) -> io::Result<()> {
    inner.file.flush()?;

    for idx in (1..=inner.keep_files).rev() {
        let src = if idx == 1 {
            inner.base_path.clone()
        } else {
            with_log_suffix(&inner.base_path, idx - 1)
        };
        let dst = with_log_suffix(&inner.base_path, idx);

        if src.exists() {
            if dst.exists() {
                fs::remove_file(&dst)?;
            }
            fs::rename(&src, &dst)?;
        }
    }

    inner.file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&inner.base_path)?;
    inner.current_size = 0;

    Ok(())
}

fn with_log_suffix(path: &Path, idx: usize) -> PathBuf {
    let name = path
        .file_name()
        .unwrap_or_else(|| OsStr::new("server.log"))
        .to_string_lossy();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{}.{}", name, idx))
}

fn load_config(cli: &Cli) -> Result<(AppConfig, bool)> {
    let file_cfg = if cli.config.exists() {
        let raw = fs::read_to_string(&cli.config)
            .with_context(|| format!("failed to read config: {}", cli.config.display()))?;
        toml::from_str::<FileConfig>(&raw)
            .with_context(|| format!("failed to parse config: {}", cli.config.display()))?
    } else {
        FileConfig {
            ip: None,
            port: None,
            token: None,
            data_dir: None,
            log_file: None,
            log_max_size_mb: None,
            log_keep_files: None,
        }
    };

    let ip = cli
        .ip
        .or_else(|| file_cfg.ip.as_deref().and_then(|s| s.parse().ok()))
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let port = cli.port.or(file_cfg.port).unwrap_or(8080);
    let token = cli.token.clone().or(file_cfg.token.clone());
    let (token, token_generated) = match token {
        Some(v) => (v, false),
        None => (Uuid::new_v4().to_string(), true),
    };
    if token.trim().is_empty() {
        return Err(anyhow!("token cannot be empty"));
    }

    let data_dir = cli
        .data_dir
        .clone()
        .or_else(|| file_cfg.data_dir.map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("data"));

    let log_file = cli
        .log_file
        .clone()
        .or_else(|| file_cfg.log_file.map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("server.log"));

    let log_max_size_mb = cli
        .log_max_size_mb
        .or(file_cfg.log_max_size_mb)
        .unwrap_or(10);
    let log_keep_files = cli.log_keep_files.or(file_cfg.log_keep_files).unwrap_or(5);

    Ok((
        AppConfig {
            ip,
            port,
            token,
            data_dir,
            log_file,
            log_max_size_bytes: log_max_size_mb.saturating_mul(1024 * 1024),
            log_keep_files,
        },
        token_generated,
    ))
}

fn init_logging(cfg: &AppConfig) -> Result<()> {
    let file_writer = RollingFileMakeWriter::new(
        cfg.log_file.clone(),
        cfg.log_max_size_bytes,
        cfg.log_keep_files,
    )?;

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_writer(std::io::stdout);

    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("fatal: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let (cfg, token_generated) = load_config(&cli)?;

    init_logging(&cfg)?;
    if token_generated {
        info!(
            "token not provided in config/cli, generated random token={}",
            cfg.token
        );
    }

    if !cfg.data_dir.exists() {
        return Err(anyhow!(
            "data directory does not exist: {}",
            cfg.data_dir.display()
        ));
    }
    let canonical_data_dir = tokio::fs::canonicalize(&cfg.data_dir)
        .await
        .with_context(|| {
            format!(
                "failed to canonicalize data dir: {}",
                cfg.data_dir.display()
            )
        })?;

    let app_state = AppState {
        token: Arc::from(cfg.token),
        data_dir: Arc::new(cfg.data_dir.clone()),
        canonical_data_dir: Arc::new(canonical_data_dir),
    };

    let app = Router::new()
        .route("/", get(download_handler))
        .with_state(app_state);

    let addr = SocketAddr::new(cfg.ip, cfg.port);
    info!(
        "server started on http://{}:{}, data_dir={}, log_file={}",
        cfg.ip,
        cfg.port,
        cfg.data_dir.display(),
        cfg.log_file.display()
    );

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    axum::serve(listener, app)
        .await
        .context("http server failed")?;

    Ok(())
}

async fn download_handler(
    State(state): State<AppState>,
    Query(query): Query<DownloadQuery>,
) -> Result<Response, (StatusCode, String)> {
    if query.token != state.token.as_ref() {
        warn!("token mismatch for filename={}", query.filename);
        return Err((StatusCode::BAD_REQUEST, "bad request".to_string()));
    }

    if !is_safe_filename(&query.filename) {
        warn!("invalid filename requested: {}", query.filename);
        return Err((StatusCode::BAD_REQUEST, "bad request".to_string()));
    }

    let path = state.data_dir.join(&query.filename);
    let canonical_target = tokio::fs::canonicalize(&path).await.map_err(|_| {
        warn!("filename not found: {}", query.filename);
        (StatusCode::BAD_REQUEST, "bad request".to_string())
    })?;

    if !canonical_target.starts_with(&*state.canonical_data_dir) {
        warn!("path traversal blocked: {}", query.filename);
        return Err((StatusCode::BAD_REQUEST, "bad request".to_string()));
    }

    let file = TokioFile::open(&canonical_target).await.map_err(|_| {
        warn!("failed to open requested filename: {}", query.filename);
        (StatusCode::BAD_REQUEST, "bad request".to_string())
    })?;
    let metadata = file.metadata().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "file metadata error".to_string(),
        )
    })?;

    if !metadata.is_file() {
        warn!(
            "requested filename is not a regular file: {}",
            query.filename
        );
        return Err((StatusCode::BAD_REQUEST, "bad request".to_string()));
    }

    let file_size = metadata.len();
    info!(
        "serving file: filename={}, size={} bytes",
        query.filename, file_size
    );

    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    resp.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&file_size.to_string()).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "header error".to_string(),
            )
        })?,
    );

    let escaped = urlencoding::encode(&query.filename);
    let disposition = format!("attachment; filename*=UTF-8''{}", escaped);
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "header error".to_string(),
            )
        })?,
    );

    Ok(resp)
}

fn is_safe_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return false;
    }
    if name == "." || name == ".." {
        return false;
    }

    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}
