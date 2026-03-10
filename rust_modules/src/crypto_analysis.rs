use std::io::Read;
use serde::Serialize;

#[derive(Serialize, Default)]
pub struct CryptoFeatures {
    pub files_count: usize,
    pub total_size: usize,
    pub entropy: f64,
    pub chi_square: f64,
    pub has_pem_keys: bool,
    pub has_certificates: bool,
    pub weak_patterns: Vec<String>,
    pub file_list: Vec<FileInfo>,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub name: String,
    pub size: usize,
    pub entropy: f64,
}

pub fn parse_zip_bytes(data: &[u8]) -> Result<CryptoFeatures, String> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("Invalid ZIP: {}", e))?;

    let mut features = CryptoFeatures::default();
    let mut all_bytes: Vec<u8> = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| format!("ZIP entry error: {}", e))?;
        if file.is_dir() {
            continue;
        }

        let name = file.name().to_string();
        let mut content = Vec::new();
        let read_limit: u64 = 50 * 1024 * 1024;
        file.by_ref().take(read_limit).read_to_end(&mut content).map_err(|e| format!("Read error: {}", e))?;

        let file_entropy = compute_shannon_entropy(&content);
        let size = content.len();

        features.file_list.push(FileInfo {
            name: name.clone(),
            size,
            entropy: file_entropy,
        });

        let content_str = String::from_utf8_lossy(&content);
        check_weak_patterns(&content_str, &name, &mut features);

        features.files_count += 1;
        features.total_size += size;
        all_bytes.extend_from_slice(&content);
    }

    features.entropy = compute_shannon_entropy(&all_bytes);
    features.chi_square = compute_chi_square(&all_bytes);

    Ok(features)
}

pub fn extract_crypto_features(content: &[u8]) -> CryptoFeatures {
    let mut features = CryptoFeatures::default();
    features.entropy = compute_shannon_entropy(content);
    features.chi_square = compute_chi_square(content);
    features.total_size = content.len();

    let text = String::from_utf8_lossy(content);
    check_weak_patterns(&text, "<input>", &mut features);

    features
}

pub fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn compute_chi_square(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    let mut chi2 = 0.0;
    for &count in &freq {
        let diff = count as f64 - expected;
        chi2 += diff * diff / expected;
    }
    chi2
}

fn check_weak_patterns(content: &str, filename: &str, features: &mut CryptoFeatures) {
    let patterns = [
        ("MD5", "Weak hash: MD5"),
        ("SHA1", "Weak hash: SHA-1"),
        ("DES", "Weak cipher: DES"),
        ("RC2", "Weak cipher: RC2"),
        ("ECB", "Weak mode: ECB"),
        ("BEGIN PRIVATE KEY", "Private key found"),
        ("BEGIN RSA PRIVATE KEY", "RSA private key found"),
        ("BEGIN CERTIFICATE", "Certificate found"),
    ];

    for (pattern, desc) in &patterns {
        if content.contains(pattern) {
            features.weak_patterns.push(format!("{} in {}", desc, filename));
        }
    }

    if content.contains("BEGIN PRIVATE KEY") || content.contains("BEGIN RSA PRIVATE KEY") {
        features.has_pem_keys = true;
    }
    if content.contains("BEGIN CERTIFICATE") {
        features.has_certificates = true;
    }
}
