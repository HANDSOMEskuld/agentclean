use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemDfRow {
    pub kind: String,
    pub total_count: Option<u64>,
    pub active: Option<u64>,
    pub size: String,
    pub reclaimable: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderDuRow {
    pub id: String,
    pub parent: String,
    pub reclaimable: bool,
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeRow {
    pub name: String,
    pub driver: String,
    pub labels: BTreeMap<String, String>,
    pub mountpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerRow {
    pub id: String,
    pub names: String,
    pub image: String,
    pub mounts: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRow {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeDisposition {
    Protected { reason: String },
    Dangerous { reason: String },
    Unknown { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerInventory {
    pub executable: Option<PathBuf>,
    pub daemon_available: bool,
    pub system_df: Vec<SystemDfRow>,
    pub builder_du: Vec<BuilderDuRow>,
    pub images: Vec<ImageRow>,
    pub containers: Vec<ContainerRow>,
    pub volumes: Vec<VolumeRow>,
    pub volume_dispositions: BTreeMap<String, VolumeDisposition>,
    pub unsupported: Vec<String>,
    pub errors: Vec<String>,
}

fn value_string(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn value_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key)
        .and_then(|x| x.as_u64().or_else(|| x.as_str()?.parse().ok()))
}
fn value_bool(v: &Value, key: &str) -> bool {
    v.get(key)
        .and_then(|x| {
            x.as_bool()
                .or_else(|| x.as_str().map(|s| s.eq_ignore_ascii_case("true")))
        })
        .unwrap_or(false)
}
fn labels(v: &Value) -> BTreeMap<String, String> {
    let raw = value_string(v, "Labels");
    if raw.is_empty() || raw == "<no value>" {
        return BTreeMap::new();
    }
    raw.split(',')
        .filter_map(|part| {
            let (k, val) = part.split_once('=')?;
            Some((k.to_owned(), val.to_owned()))
        })
        .collect()
}
fn json_lines(input: &str) -> Result<Vec<Value>> {
    input
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).with_context(|| format!("invalid Docker JSON line: {line}"))
        })
        .collect()
}

fn required_string(v: &Value, key: &str) -> Result<String> {
    let value = v
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Docker JSON object missing non-empty string field {key:?}"))?;
    Ok(value.to_owned())
}

pub fn parse_system_df_json(input: &str) -> Result<Vec<SystemDfRow>> {
    Ok(json_lines(input)?
        .into_iter()
        .map(|v| SystemDfRow {
            kind: value_string(&v, "Type"),
            total_count: value_u64(&v, "TotalCount"),
            active: value_u64(&v, "Active"),
            size: value_string(&v, "Size"),
            reclaimable: value_string(&v, "Reclaimable"),
        })
        .collect())
}
pub fn parse_builder_du_json(input: &str) -> Result<Vec<BuilderDuRow>> {
    Ok(json_lines(input)?
        .into_iter()
        .map(|v| BuilderDuRow {
            id: value_string(&v, "ID"),
            parent: value_string(&v, "Parent"),
            reclaimable: value_bool(&v, "Reclaimable"),
            size: value_string(&v, "Size"),
        })
        .collect())
}
pub fn parse_volume_ls_json(input: &str) -> Result<Vec<VolumeRow>> {
    json_lines(input)?
        .into_iter()
        .map(|v| {
            Ok(VolumeRow {
                name: required_string(&v, "Name")?,
                driver: value_string(&v, "Driver"),
                labels: labels(&v),
                mountpoint: value_string(&v, "Mountpoint"),
            })
        })
        .collect()
}
pub fn parse_container_ls_json(input: &str) -> Result<Vec<ContainerRow>> {
    json_lines(input)?
        .into_iter()
        .map(|v| {
            Ok(ContainerRow {
                id: required_string(&v, "ID")?,
                names: value_string(&v, "Names"),
                image: value_string(&v, "Image"),
                mounts: value_string(&v, "Mounts"),
                labels: labels(&v),
            })
        })
        .collect()
}
pub fn parse_image_ls_json(input: &str) -> Result<Vec<ImageRow>> {
    json_lines(input)?
        .into_iter()
        .map(|v| {
            Ok(ImageRow {
                id: required_string(&v, "ID")?,
                repository: value_string(&v, "Repository"),
                tag: value_string(&v, "Tag"),
                size: value_string(&v, "Size"),
            })
        })
        .collect()
}

pub fn parse_container_inspect_json(input: &str) -> Result<Vec<String>> {
    let values: Vec<Value> = match serde_json::from_str(input) {
        Ok(values) => values,
        Err(_) => json_lines(input)?,
    };
    let mut names = Vec::new();
    for container in values {
        if let Some(mounts) = container.get("Mounts").and_then(Value::as_array) {
            for mount in mounts {
                if mount.get("Type").and_then(Value::as_str) == Some("volume") {
                    if let Some(name) = mount
                        .get("Name")
                        .and_then(Value::as_str)
                        .filter(|n| !n.is_empty())
                    {
                        names.push(name.to_owned());
                    }
                }
            }
        }
    }
    Ok(names)
}

pub fn classify_volume(name: &str, labels_text: &str, referenced: bool) -> VolumeDisposition {
    let haystack = format!("{name} {labels_text}").to_ascii_lowercase();
    const DB_NAMES: &[&str] = &[
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongo",
        "mongodb",
        "redis",
        "redisdata",
        "sqlite",
        "cassandra",
        "influx",
        "elasticsearch",
        "db_data",
        "database",
    ];
    if DB_NAMES.iter().any(|word| haystack.contains(word)) {
        return VolumeDisposition::Protected {
            reason: "database-like name".into(),
        };
    }
    if referenced {
        return VolumeDisposition::Protected {
            reason: "referenced by container".into(),
        };
    }
    if name.trim().is_empty() {
        return VolumeDisposition::Unknown {
            reason: "unnamed volume".into(),
        };
    }
    VolumeDisposition::Dangerous {
        reason: "unreferenced volume may contain data".into(),
    }
}

pub fn docker_executable() -> Option<PathBuf> {
    std::env::var_os("DOCKER_BINARY")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| {
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|p| p.join("docker"))
                    .find(|p| p.is_file())
            })
        })
}
pub fn is_docker_socket(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                m.file_type().is_socket()
            }
            #[cfg(not(unix))]
            {
                m.is_file()
            }
        })
        .unwrap_or(false)
}

fn run_read_only(docker: &Path, args: &[&str], timeout: Duration) -> Result<String> {
    let mut child = Command::new(docker)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {}", docker.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("missing Docker stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("missing Docker stderr pipe"))?;
    let stdout_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = std::io::BufReader::new(stdout).read_to_end(&mut bytes);
        (result, bytes)
    });
    let stderr_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = std::io::BufReader::new(stderr).read_to_end(&mut bytes);
        (result, bytes)
    });
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let (_, stdout) = stdout_thread
                .join()
                .map_err(|_| anyhow!("stdout drain panicked"))?;
            let (_, stderr) = stderr_thread
                .join()
                .map_err(|_| anyhow!("stderr drain panicked"))?;
            if !status.success() {
                return Err(anyhow!(
                    "docker {} failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&stderr).trim()
                ));
            }
            return String::from_utf8(stdout).context("Docker output was not UTF-8");
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            return Err(anyhow!("docker {} timed out", args.join(" ")));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub fn inventory(timeout_secs: u64) -> Result<Vec<String>> {
    let report = analyze(Duration::from_secs(timeout_secs));
    Ok(report
        .errors
        .into_iter()
        .chain(report.unsupported)
        .collect())
}

pub fn analyze(timeout: Duration) -> DockerInventory {
    let executable = docker_executable();
    let mut report = DockerInventory {
        executable: executable.clone(),
        daemon_available: false,
        system_df: vec![],
        builder_du: vec![],
        images: vec![],
        containers: vec![],
        volumes: vec![],
        volume_dispositions: BTreeMap::new(),
        unsupported: vec![],
        errors: vec![],
    };
    let Some(docker) = executable else {
        report
            .unsupported
            .push("docker executable not found".into());
        return report;
    };
    if run_read_only(
        &docker,
        &["info", "--format", "{{.ServerVersion}}"],
        timeout,
    )
    .is_err()
    {
        report.unsupported.push("Docker daemon unavailable".into());
        return report;
    }
    report.daemon_available = true;
    let commands: &[(&str, &[&str])] = &[
        ("system df", &["system", "df", "--format", "{{json .}}"]),
        ("builder du", &["builder", "du", "--format", "{{json .}}"]),
        ("images", &["image", "ls", "--format", "{{json .}}"]),
        (
            "containers",
            &["container", "ls", "-a", "--format", "{{json .}}"],
        ),
        ("volumes", &["volume", "ls", "--format", "{{json .}}"]),
    ];
    for (name, args) in commands {
        match run_read_only(&docker, args, timeout) {
            Ok(out) => match *name {
                "system df" => {
                    report.system_df = parse_system_df_json(&out).unwrap_or_else(|e| {
                        report.errors.push(format!("{name}: {e}"));
                        vec![]
                    })
                }
                "builder du" => {
                    report.builder_du = parse_builder_du_json(&out).unwrap_or_else(|e| {
                        report.unsupported.push(format!("{name}: {e}"));
                        vec![]
                    })
                }
                "images" => {
                    report.images = parse_image_ls_json(&out).unwrap_or_else(|e| {
                        report.errors.push(format!("{name}: {e}"));
                        vec![]
                    })
                }
                "containers" => {
                    report.containers = parse_container_ls_json(&out).unwrap_or_else(|e| {
                        report.errors.push(format!("{name}: {e}"));
                        vec![]
                    })
                }
                "volumes" => {
                    report.volumes = parse_volume_ls_json(&out).unwrap_or_else(|e| {
                        report.errors.push(format!("{name}: {e}"));
                        vec![]
                    })
                }
                _ => {}
            },
            Err(e) => report.unsupported.push(format!("{name}: {e}")),
        }
    }
    let mut referenced_names: Option<std::collections::BTreeSet<String>> = None;
    if !report.containers.is_empty() {
        let ids: Vec<&str> = report
            .containers
            .iter()
            .map(|container| container.id.as_str())
            .collect();
        let mut inspect_args = vec!["inspect"];
        inspect_args.extend(ids);
        match run_read_only(&docker, &inspect_args, timeout) {
            Ok(out) => match parse_container_inspect_json(&out) {
                Ok(names) => referenced_names = Some(names.into_iter().collect()),
                Err(e) => report.errors.push(format!("container inspect: {e}")),
            },
            Err(e) => report.errors.push(format!("container inspect: {e}")),
        }
    }
    for volume in &report.volumes {
        let referenced = referenced_names
            .as_ref()
            .map(|names| names.contains(&volume.name))
            .unwrap_or(true);
        let label_text = volume
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        report.volume_dispositions.insert(
            volume.name.clone(),
            classify_volume(&volume.name, &label_text, referenced),
        );
    }
    report
}
