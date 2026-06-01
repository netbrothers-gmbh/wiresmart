use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use eframe::egui;
use serde::{Deserialize, Serialize};

#[cfg(not(target_os = "linux"))]
compile_error!("WireSmart supports Linux only.");

const LINE_HEIGHT_FACTOR: f32 = 1.2;
const HELPER_SERVER_FLAG: &str = "--helper-server";

#[derive(Serialize, Deserialize)]
enum HelperRequest {
    Ping,
    ListConfigs { dirs: Vec<PathBuf> },
    WgQuick { action: String, path: PathBuf },
    Quit,
}

#[derive(Serialize, Deserialize)]
enum HelperResponse {
    Pong,
    Configs { paths: Vec<PathBuf> },
    Ok,
    Error { message: String },
}

struct HelperClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl HelperClient {
    fn request(&mut self, request: &HelperRequest) -> Result<HelperResponse, String> {
        let payload =
            serde_json::to_string(request).map_err(|err| format!("Helper encode error: {}", err))?;

        self.stdin
            .write_all(payload.as_bytes())
            .map_err(|err| format!("Helper write error: {}", err))?;
        self.stdin
            .write_all(b"\n")
            .map_err(|err| format!("Helper write error: {}", err))?;
        self.stdin
            .flush()
            .map_err(|err| format!("Helper flush error: {}", err))?;

        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .map_err(|err| format!("Helper read error: {}", err))?;

        if read == 0 {
            return Err("Privileged helper disconnected".to_owned());
        }

        let response: HelperResponse = serde_json::from_str(line.trim_end())
            .map_err(|err| format!("Helper decode error: {}", err))?;

        match response {
            HelperResponse::Error { message } => Err(message),
            other => Ok(other),
        }
    }
}

impl Drop for HelperClient {
    fn drop(&mut self) {
        if let Ok(payload) = serde_json::to_string(&HelperRequest::Quit) {
            let _ = self.stdin.write_all(payload.as_bytes());
            let _ = self.stdin.write_all(b"\n");
            let _ = self.stdin.flush();
        }

        let _ = self.child.kill();
    }
}

#[derive(Clone)]
struct Tunnel {
    name: String,
    path: PathBuf,
}

struct WireSmartApp {
    tunnels: Vec<Tunnel>,
    active_interfaces: HashSet<String>,
    info_message: String,
    error_message: Option<String>,
    custom_config_dir: String,
    wg_quick_available: bool,
    pkexec_available: bool,
    helper: Option<HelperClient>,
    logo: Option<egui::TextureHandle>,
    style_scaled: bool,
}

impl WireSmartApp {
    fn new() -> Self {
        let mut app = Self {
            tunnels: Vec::new(),
            active_interfaces: HashSet::new(),
            info_message: "Discovering WireGuard tunnels...".to_owned(),
            error_message: None,
            custom_config_dir: String::new(),
            wg_quick_available: check_command_exists("wg-quick"),
            pkexec_available: check_command_exists("pkexec"),
            helper: None,
            logo: None,
            style_scaled: false,
        };

        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.error_message = None;

        match self.discover_tunnels_with_privilege() {
            Ok(tunnels) => {
                self.tunnels = tunnels;
                self.info_message = format!("Found {} tunnel(s)", self.tunnels.len());
            }
            Err(err) => {
                self.tunnels.clear();
                self.error_message = Some(err);
            }
        }

        self.refresh_status();
    }

    fn refresh_status(&mut self) {
        self.active_interfaces.clear();
        if let Ok(output) = Command::new("wg").arg("show").arg("interfaces").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                self.active_interfaces = stdout
                    .split_whitespace()
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .collect();
            }
        }
    }

    fn custom_dir(&self) -> Option<PathBuf> {
        let trimmed = self.custom_config_dir.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    }

    fn default_config_dir_display(&self) -> String {
        let candidates = candidate_config_dirs(None);

        if let Some(existing) = candidates.iter().find(|dir| dir.exists()) {
            return existing.display().to_string();
        }

        if let Some(first) = candidates.first() {
            return first.display().to_string();
        }

        "/etc/wireguard".to_owned()
    }

    fn run_wg_quick(&mut self, action: &str, tunnel: &Tunnel) {
        self.error_message = None;

        if !self.wg_quick_available {
            self.error_message = Some("wg-quick is not available in PATH".to_owned());
            return;
        }

        if !is_effective_root() {
            if let Err(err) = self.ensure_helper_available() {
                self.error_message = Some(permission_guidance_message());
                self.error_message = Some(err);
                return;
            }

            let response = {
                let helper = self.helper.as_mut().expect("helper must exist");
                helper.request(&HelperRequest::WgQuick {
                    action: action.to_owned(),
                    path: tunnel.path.clone(),
                })
            };

            match response {
                Ok(HelperResponse::Ok) => {
                    self.info_message = format!("Successfully ran wg-quick {} {}.", action, tunnel.name);
                    self.refresh_status();
                }
                Ok(_) => {
                    self.error_message = Some("Unexpected helper response".to_owned());
                }
                Err(err) => {
                    self.error_message = Some(err);
                }
            }
            return;
        }

        let output = Command::new("wg-quick")
            .arg(action)
            .arg(&tunnel.path)
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    self.info_message =
                        format!("Successfully ran wg-quick {} {}.", action, tunnel.name);
                    self.refresh_status();
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let message = stderr.trim();
                    if message.is_empty() {
                        self.error_message =
                            Some(format!("wg-quick {} failed for {}", action, tunnel.name));
                    } else {
                        self.error_message =
                            Some(format!("wg-quick {} failed: {}", action, message));
                    }
                }
            }
            Err(err) => {
                self.error_message = Some(format!("Failed to start wg-quick: {}", err));
            }
        }
    }

    fn ensure_helper_available(&mut self) -> Result<(), String> {
        if !self.pkexec_available || !has_graphical_session() {
            return Err(permission_guidance_message());
        }

        if let Some(helper) = self.helper.as_mut() {
            if matches!(helper.request(&HelperRequest::Ping), Ok(HelperResponse::Pong)) {
                return Ok(());
            }
            self.helper = None;
        }

        let mut helper = start_privileged_helper()?;
        match helper.request(&HelperRequest::Ping) {
            Ok(HelperResponse::Pong) => {
                self.helper = Some(helper);
                Ok(())
            }
            Ok(_) => Err("Unexpected helper handshake response".to_owned()),
            Err(err) => Err(err),
        }
    }

    fn discover_tunnels_with_privilege(&mut self) -> Result<Vec<Tunnel>, String> {
        let mut entries: BTreeMap<String, Tunnel> = BTreeMap::new();
        let mut permission_blocked = false;

        for directory in candidate_config_dirs(self.custom_dir()) {
            if !directory.exists() {
                continue;
            }

            let read_dir = match fs::read_dir(&directory) {
                Ok(read_dir) => read_dir,
                Err(err) => {
                    if err.kind() == ErrorKind::PermissionDenied {
                        if self.pkexec_available && has_graphical_session() {
                            self.ensure_helper_available()?;

                            let response = {
                                let helper = self.helper.as_mut().expect("helper must exist");
                                helper.request(&HelperRequest::ListConfigs {
                                    dirs: vec![directory.clone()],
                                })
                            }?;

                            match response {
                                HelperResponse::Configs { paths } => {
                                    for path in paths {
                                        insert_tunnel_from_path(&mut entries, path);
                                    }
                                }
                                _ => return Err("Unexpected helper response".to_owned()),
                            }

                            continue;
                        }

                        permission_blocked = true;
                        continue;
                    }

                    return Err(format!("Cannot read {}: {}", directory.display(), err));
                }
            };

            for item in read_dir {
                let item =
                    item.map_err(|err| format!("Failed reading directory entry: {}", err))?;
                let path = item.path();

                if !path.is_file() {
                    continue;
                }

                let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };

                if !file_name.ends_with(".conf") {
                    continue;
                }

                insert_tunnel_from_path(&mut entries, path);
            }
        }

        if entries.is_empty() && permission_blocked {
            return Err(permission_guidance_message());
        }

        Ok(entries.into_values().collect())
    }
}

fn scale_text_styles(ctx: &egui::Context, factor: f32) {
    ctx.style_mut(|style| {
        for font_id in style.text_styles.values_mut() {
            font_id.size *= factor;
        }
    });
}

fn text_with_line_height(
    ui: &egui::Ui,
    text: impl Into<String>,
    text_style: egui::TextStyle,
) -> egui::RichText {
    let line_height = ui.text_style_height(&text_style) * LINE_HEIGHT_FACTOR;
    egui::RichText::new(text)
        .text_style(text_style)
        .line_height(Some(line_height))
}

impl eframe::App for WireSmartApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.style_scaled {
            scale_text_styles(ctx, 1.12);
            self.style_scaled = true;
        }

        egui::TopBottomPanel::bottom("status_bar")
            .resizable(false)
            .exact_height(20.0)
            .show(ctx, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::LEFT), |ui| {
                    ui.label(egui::RichText::new(self.info_message.as_str()).small());
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Load logo texture once (if available)
            if self.logo.is_none() {
                if let Ok(color_image) = (|| -> Result<egui::ColorImage, String> {
                    let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/logo.png"));
                    let dynimg = image::load_from_memory(bytes).map_err(|e| e.to_string())?;
                    let rgba = dynimg.to_rgba8();
                    let size = [rgba.width() as usize, rgba.height() as usize];
                    let pixels = rgba.into_raw();
                    Ok(egui::ColorImage::from_rgba_unmultiplied(size, &pixels))
                })() {
                    let tex = ctx.load_texture("logo", color_image, egui::TextureOptions::default());
                    self.logo = Some(tex);
                }
            }

            ui.horizontal(|ui| {
                if let Some(tex) = &self.logo {
                    ui.add(egui::Image::new((tex.id(), egui::vec2(32.0, 32.0))));
                    ui.add_space(4.0);
                }

                ui.add(egui::Label::new(egui::RichText::new("NB WireSmart").heading().color(egui::Color32::from_rgb(0x00, 0x7a, 0xfa))));
            });
            ui.add_space(4.0);

            if !self.wg_quick_available {
                ui.colored_label(
                    egui::Color32::RED,
                    text_with_line_height(ui, "wg-quick not found in PATH.", egui::TextStyle::Body),
                );
            }

            if !self.pkexec_available {
                ui.colored_label(
                    egui::Color32::RED,
                    text_with_line_height(
                        ui,
                        "pkexec not found in PATH. Automatic privilege dialog is unavailable.",
                        egui::TextStyle::Body,
                    ),
                );
            }

            ui.separator();

            ui.horizontal(|ui| {
                let default_dir_hint = self.default_config_dir_display();
                ui.label(text_with_line_height(
                    ui,
                    "Config directory:",
                    egui::TextStyle::Body,
                ));
                ui.add(
                    egui::TextEdit::singleline(&mut self.custom_config_dir)
                        .hint_text(default_dir_hint),
                );
                if ui
                    .button(text_with_line_height(
                        ui,
                        "Rescan",
                        egui::TextStyle::Button,
                    ))
                    .clicked()
                {
                    self.refresh();
                }
            });

            if let Some(error) = &self.error_message {
                ui.colored_label(
                    egui::Color32::RED,
                    text_with_line_height(ui, error.as_str(), egui::TextStyle::Body),
                );
            }

            ui.separator();
            ui.label(text_with_line_height(
                ui,
                "Discovered tunnels:",
                egui::TextStyle::Body,
            ));

            let mut pending_toggle: Option<(&'static str, Tunnel)> = None;
            let tunnels_area_height = ui.available_height().max(0.0);
            egui::ScrollArea::vertical()
                .max_height(tunnels_area_height)
                .show(ui, |ui| {
                    for tunnel in &self.tunnels {
                        let is_active = self.active_interfaces.contains(&tunnel.name);
                        let status_color = if is_active {
                            egui::Color32::from_rgb(0x27, 0xae, 0x60)
                        } else {
                            egui::Color32::from_rgb(0xf1, 0xc4, 0x0f)
                        };

                        let button_text = format!("     {}", tunnel.name);
                        let response = ui.add(egui::Button::new(text_with_line_height(
                            ui,
                            button_text,
                            egui::TextStyle::Body,
                        )));

                        let dot_center = egui::pos2(response.rect.left() + 12.0, response.rect.center().y);
                        ui.painter().circle_filled(dot_center, 4.0, status_color);

                        if response.clicked() {
                            let action = if is_active { "down" } else { "up" };
                            pending_toggle = Some((action, tunnel.clone()));
                        }
                    }
                });

            if let Some((action, tunnel)) = pending_toggle {
                self.run_wg_quick(action, &tunnel);
            }
        });
    }
}

fn insert_tunnel_from_path(entries: &mut BTreeMap<String, Tunnel>, path: PathBuf) {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };

    let Some(stem) = Path::new(file_name)
        .file_stem()
        .and_then(|stem| stem.to_str())
    else {
        return;
    };

    entries.entry(stem.to_owned()).or_insert(Tunnel {
        name: stem.to_owned(),
        path,
    });
}

fn start_privileged_helper() -> Result<HelperClient, String> {
    let executable = env::current_exe()
        .map_err(|err| format!("Failed to resolve app executable path: {}", err))?;

    let mut child = Command::new("pkexec")
        .arg("--disable-internal-agent")
        .arg(executable)
        .arg(HELPER_SERVER_FLAG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| format!("Failed to start privilege dialog (pkexec): {}", err))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Failed to connect to helper stdin".to_owned())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to connect to helper stdout".to_owned())?;

    Ok(HelperClient {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

fn run_helper_server() -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|err| format!("Helper read error: {}", err))?;

        if read == 0 {
            break;
        }

        let request: HelperRequest = match serde_json::from_str(line.trim_end()) {
            Ok(request) => request,
            Err(err) => {
                let response = HelperResponse::Error {
                    message: format!("Invalid helper request: {}", err),
                };
                if !write_helper_response(&mut writer, &response)? {
                    break;
                }
                continue;
            }
        };

        let should_quit = matches!(request, HelperRequest::Quit);
        let response = handle_helper_request(request);

        if !write_helper_response(&mut writer, &response)? {
            break;
        }

        if should_quit {
            break;
        }
    }

    Ok(())
}

fn write_helper_response(writer: &mut impl Write, response: &HelperResponse) -> Result<bool, String> {
    let payload =
        serde_json::to_string(response).map_err(|err| format!("Helper encode error: {}", err))?;

    if let Err(err) = writer.write_all(payload.as_bytes()) {
        if err.kind() == ErrorKind::BrokenPipe {
            return Ok(false);
        }
        return Err(format!("Helper write error: {}", err));
    }

    if let Err(err) = writer.write_all(b"\n") {
        if err.kind() == ErrorKind::BrokenPipe {
            return Ok(false);
        }
        return Err(format!("Helper write error: {}", err));
    }

    if let Err(err) = writer.flush() {
        if err.kind() == ErrorKind::BrokenPipe {
            return Ok(false);
        }
        return Err(format!("Helper flush error: {}", err));
    }

    Ok(true)
}

fn handle_helper_request(request: HelperRequest) -> HelperResponse {
    match request {
        HelperRequest::Ping => HelperResponse::Pong,
        HelperRequest::ListConfigs { dirs } => {
            let mut paths = Vec::new();

            for directory in dirs {
                if !directory.exists() {
                    continue;
                }

                let read_dir = match fs::read_dir(&directory) {
                    Ok(read_dir) => read_dir,
                    Err(err) => {
                        return HelperResponse::Error {
                            message: format!("Cannot read {}: {}", directory.display(), err),
                        }
                    }
                };

                for entry in read_dir {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            return HelperResponse::Error {
                                message: format!("Failed reading directory entry: {}", err),
                            }
                        }
                    };

                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }

                    if path.extension().and_then(|ext| ext.to_str()) == Some("conf") {
                        paths.push(path);
                    }
                }
            }

            HelperResponse::Configs { paths }
        }
        HelperRequest::WgQuick { action, path } => {
            let output = match Command::new("wg-quick").arg(&action).arg(&path).output() {
                Ok(output) => output,
                Err(err) => {
                    return HelperResponse::Error {
                        message: format!("Failed to start wg-quick: {}", err),
                    }
                }
            };

            if output.status.success() {
                HelperResponse::Ok
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let message = stderr.trim();
                if message.is_empty() {
                    HelperResponse::Error {
                        message: format!("wg-quick {} failed for {}", action, path.display()),
                    }
                } else {
                    HelperResponse::Error {
                        message: format!("wg-quick {} failed: {}", action, message),
                    }
                }
            }
        }
        HelperRequest::Quit => HelperResponse::Ok,
    }
}

fn has_graphical_session() -> bool {
    env::var_os("WAYLAND_DISPLAY").is_some()
        || env::var_os("WAYLAND_SOCKET").is_some()
        || env::var_os("DISPLAY").is_some()
}

fn is_effective_root() -> bool {
    match Command::new("id").arg("-u").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim() == "0"
        }
        _ => false,
    }
}

fn permission_guidance_message() -> String {
    "Insufficient privileges, and no graphical privilege dialog is available. Please re-run NB WireSmart as a user with the required privileges (for example via sudo).".to_owned()
}

fn candidate_config_dirs(custom_dir: Option<PathBuf>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(dir) = custom_dir {
        dirs.push(dir);
    }

    if let Some(env_dir) = env::var_os("WG_QUICK_CONFIG_DIR") {
        dirs.push(PathBuf::from(env_dir));
    }

    #[cfg(target_os = "linux")]
    {
        dirs.push(PathBuf::from("/etc/wireguard"));
    }

    if let Some(home) = env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".config/wireguard"));
    }

    let mut unique = Vec::new();
    for dir in dirs {
        if !unique.iter().any(|existing| existing == &dir) {
            unique.push(dir);
        }
    }
    unique
}

fn check_command_exists(command: &str) -> bool {
    Command::new(command).arg("--version").output().is_ok()
}

fn main() -> eframe::Result<()> {
    let mut args = env::args();
    let _ = args.next();
    if args.next().as_deref() == Some(HELPER_SERVER_FLAG) {
        if let Err(err) = run_helper_server() {
            eprintln!("{}", err);
            std::process::exit(1);
        }

        return Ok(());
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("de.netbrothers.wiresmart")
            .with_inner_size([640.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "NB WireSmart",
        native_options,
        Box::new(|_cc| Ok(Box::new(WireSmartApp::new()))),
    )
}
