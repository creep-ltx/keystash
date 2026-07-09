use zeroize::Zeroize;

// ─────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Good,
    Weak,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Good => "Good",
            Severity::Weak => "Weak",
            Severity::Critical => "Critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub title: String,
    pub category: String,
    pub username: String,
    pub severity: Severity,
    /// Human-readable list of detected issues. Empty when severity == Good.
    pub issues: Vec<String>,
    /// 0–5 composite strength score (higher = stronger).
    pub score: u8,
    /// None = not checked, Some(0) = not pwned, Some(n) = found in n breaches.
    pub hibp_count: Option<u64>,
}

pub struct AuditReport {
    /// Sorted: Critical first, then Weak, then Good.
    pub entries: Vec<AuditEntry>,
    pub critical_count: usize,
    pub weak_count: usize,
    pub good_count: usize,
    /// Groups of entry IDs/titles that share the same password.
    pub duplicate_groups: Vec<Vec<String>>,
}

// ─────────────────────────────────────────────
//  Known weak passwords (small embedded list)
// ─────────────────────────────────────────────

const COMMON_WEAK: &[&str] = &[
    "password", "password1", "password123", "123456", "12345678", "123456789",
    "1234567890", "qwerty", "qwerty123", "abc123", "letmein", "admin", "admin123",
    "welcome", "welcome1", "monkey", "dragon", "master", "shadow", "sunshine",
    "princess", "iloveyou", "trustno1", "hello", "hello123", "test", "test123",
    "changeme", "secret", "pass", "pass123", "root", "toor", "login",
];

// ─────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────

/// Audit a list of decrypted passwords.
///
/// `records` is `(id, title, category, username, plaintext_password)`.
/// Passwords are zeroized inside `run_full_audit` before the function returns.
pub fn audit_passwords(records: &mut Vec<(i64, String, String, String, String)>) -> AuditReport {
    run_full_audit(records)
}

/// Internal implementation that does a single pass: hash → zeroize → report.
fn run_full_audit(records: &mut Vec<(i64, String, String, String, String)>) -> AuditReport {
    use std::collections::HashMap;

    // First pass: collect sha256 fingerprints before zeroizing.
    let fingerprints: Vec<[u8; 32]> = records
        .iter()
        .map(|(_, _, _, _, pw)| sha256(pw.as_bytes()))
        .collect();

    // Build duplicate map: fingerprint → list of (title, id)
    let mut fp_map: HashMap<[u8; 32], Vec<(i64, String)>> = HashMap::new();
    for (i, (id, title, _, _, _)) in records.iter().enumerate() {
        fp_map.entry(fingerprints[i]).or_default().push((*id, title.clone()));
    }
    let duplicate_groups: Vec<Vec<String>> = fp_map
        .values()
        .filter(|group| group.len() > 1)
        .map(|group| group.iter().map(|(_, title)| title.clone()).collect())
        .collect();

    // Second pass: strength audit + zeroize
    let mut entries: Vec<AuditEntry> = records
        .iter_mut()
        .enumerate()
        .map(|(i, (id, title, category, username, password))| {
            let (mut severity, mut issues, score) = check_strength(password);

            // Mark duplicates as Critical
            let fp = &fingerprints[i];
            if let Some(group) = fp_map.get(fp) {
                if group.len() > 1 {
                    issues.push(format!(
                        "Password reused across {} entries",
                        group.len()
                    ));
                    if severity != Severity::Critical {
                        severity = Severity::Critical;
                    }
                }
            }

            password.zeroize();

            AuditEntry {
                id: *id,
                title: title.clone(),
                category: category.clone(),
                username: username.clone(),
                severity,
                issues,
                score,
                hibp_count: None,
            }
        })
        .collect();

    // Sort: Critical first → Weak → Good, then alphabetically by title
    entries.sort_by(|a, b| {
        b.severity.cmp(&a.severity).then(a.title.cmp(&b.title))
    });

    let critical_count = entries.iter().filter(|e| e.severity == Severity::Critical).count();
    let weak_count = entries.iter().filter(|e| e.severity == Severity::Weak).count();
    let good_count = entries.iter().filter(|e| e.severity == Severity::Good).count();

    AuditReport {
        entries,
        critical_count,
        weak_count,
        good_count,
        duplicate_groups,
    }
}

// ─────────────────────────────────────────────
//  Strength checker
// ─────────────────────────────────────────────

/// Scores by estimated brute-force entropy (character-pool size ^ length, in
/// bits) rather than the additive-points scheme this replaced. The old scheme
/// capped out at 5 points needing every charset class present, so a 40-char
/// random lowercase passphrase -- genuinely excellent -- scored only 2 points
/// and was reported "Critical" right alongside "password123", while a short
/// "Aa1!" that happened to touch all four classes scored higher. Entropy is
/// what actually determines how hard a password is to brute-force, so it's
/// what determines severity here instead.
fn check_strength(password: &str) -> (Severity, Vec<String>, u8) {
    let mut issues = Vec::new();

    let n_chars = password.chars().count();
    let has_upper  = password.chars().any(|c| c.is_uppercase());
    let has_lower  = password.chars().any(|c| c.is_lowercase());
    let has_digit  = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());
    let lower_pw   = password.to_lowercase();
    let is_common  = COMMON_WEAK.contains(&lower_pw.as_str());

    // Empty / blank
    if n_chars == 0 {
        issues.push("Password is empty".to_string());
        return (Severity::Critical, issues, 0);
    }

    // Common password check (overrides everything)
    if is_common {
        issues.push("Password is a known common/weak password".to_string());
        return (Severity::Critical, issues, 0);
    }

    // Repeated characters (e.g. "aaaaaaa")
    let all_same = password.chars().all(|c| c == password.chars().next().unwrap_or(' '));
    if all_same {
        issues.push("Password consists of a single repeated character".to_string());
        return (Severity::Critical, issues, 0);
    }

    let mut pool: f64 = 0.0;
    if has_lower  { pool += 26.0; }
    if has_upper  { pool += 26.0; }
    if has_digit  { pool += 10.0; }
    if has_symbol { pool += 33.0; }
    let mut entropy_bits = (n_chars as f64) * pool.max(1.0).log2();

    // Sequential strings (e.g. "12345678", "abcdefgh") are trivially guessable
    // regardless of what their raw pool size implies.
    let sequential = is_sequential(password);
    if sequential {
        entropy_bits = (entropy_bits - 20.0).max(0.0);
    }

    let severity = if entropy_bits >= 75.0 {
        Severity::Good
    } else if entropy_bits >= 50.0 {
        Severity::Weak
    } else {
        Severity::Critical
    };

    // AuditEntry::issues is documented as empty when severity == Good, so
    // charset/length nitpicks only get surfaced once they've actually
    // affected the outcome -- otherwise a long, Good-rated lowercase
    // passphrase would still show "No uppercase letters" etc. as if it were
    // a problem.
    if severity != Severity::Good {
        if n_chars < 8 {
            issues.push(format!("Too short ({} chars, minimum 8 recommended)", n_chars));
        }
        if !has_upper  { issues.push("No uppercase letters".to_string()); }
        if !has_digit  { issues.push("No numbers".to_string()); }
        if !has_symbol { issues.push("No special characters".to_string()); }
        if sequential {
            issues.push("Password is a sequential pattern (e.g. 12345678, abcdefgh)".to_string());
        }
    }

    // Displayed elsewhere as an out-of-5 bar; 20 bits/point lines up with the
    // Good threshold above (a 16-char all-lowercase passphrase, ~75 bits,
    // lands at a full bar).
    let score = (entropy_bits / 20.0).min(5.0) as u8;

    (severity, issues, score)
}

fn is_sequential(s: &str) -> bool {
    if s.len() < 4 {
        return false;
    }
    let bytes = s.as_bytes();
    // Check ascending sequence
    let ascending = bytes.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    // Check descending sequence
    let descending = bytes.windows(2).all(|w| w[1] == w[0].wrapping_sub(1));
    ascending || descending
}

// ─────────────────────────────────────────────
//  Tiny SHA-256 (no extra dep — uses ring/sha2
//  if available, otherwise inline pure-Rust)
// ─────────────────────────────────────────────

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use std::num::Wrapping;

    // Pure-Rust SHA-256 (RFC 6234)
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];

    let mut h: [Wrapping<u32>; 8] = [
        Wrapping(0x6a09e667), Wrapping(0xbb67ae85), Wrapping(0x3c6ef372), Wrapping(0xa54ff53a),
        Wrapping(0x510e527f), Wrapping(0x9b05688c), Wrapping(0x1f83d9ab), Wrapping(0x5be0cd19),
    ];

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit chunk
    for chunk in msg.chunks(64) {
        let mut w = [Wrapping(0u32); 64];
        for i in 0..16 {
            w[i] = Wrapping(u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]));
        }
        for i in 16..64 {
            let s0 = w[i-15].0.rotate_right(7) ^ w[i-15].0.rotate_right(18) ^ (w[i-15].0 >> 3);
            let s1 = w[i-2].0.rotate_right(17) ^ w[i-2].0.rotate_right(19) ^ (w[i-2].0 >> 10);
            w[i] = Wrapping(w[i-16].0.wrapping_add(s0).wrapping_add(w[i-7].0).wrapping_add(s1));
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.0.rotate_right(6) ^ e.0.rotate_right(11) ^ e.0.rotate_right(25);
            let ch = (e.0 & f.0) ^ ((!e.0) & g.0);
            let temp1 = Wrapping(hh.0.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i].0));
            let s0 = a.0.rotate_right(2) ^ a.0.rotate_right(13) ^ a.0.rotate_right(22);
            let maj = (a.0 & b.0) ^ (a.0 & c.0) ^ (b.0 & c.0);
            let temp2 = Wrapping(s0.wrapping_add(maj));
            hh = g; g = f; f = e;
            e = Wrapping(d.0.wrapping_add(temp1.0));
            d = c; c = b; b = a;
            a = Wrapping(temp1.0.wrapping_add(temp2.0));
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.0.to_be_bytes());
    }
    out
}

// ─────────────────────────────────────────────
//  HaveIBeenPwned k-anonymity check
// ─────────────────────────────────────────────

/// Check a password against the HaveIBeenPwned Passwords API using k-anonymity.
///
/// Only the first 5 hex characters of the SHA-1 hash are sent to the server.
/// Returns `Ok(0)` if not found, `Ok(n)` if found in `n` breach records,
/// or `Err(msg)` on network/parse failure.
pub fn check_hibp(password: &str) -> Result<u64, String> {
    let hash_bytes = sha1(password.as_bytes());
    let hash_hex: String = hash_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let prefix = &hash_hex[..5];
    let suffix = &hash_hex[5..];

    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    let response = ureq::get(&url)
        .set("User-Agent", "keystash-password-manager")
        .call()
        .map_err(|e| format!("HIBP request failed: {}", e))?;

    let body = response
        .into_string()
        .map_err(|e| format!("HIBP response read error: {}", e))?;

    for line in body.lines() {
        // Each line: "HASH_SUFFIX:COUNT"
        if let Some((line_suffix, count_str)) = line.split_once(':') {
            if line_suffix.eq_ignore_ascii_case(suffix) {
                return Ok(count_str.trim().parse().unwrap_or(1));
            }
        }
    }

    Ok(0) // not in breach list
}

// ─────────────────────────────────────────────
//  Pure-Rust SHA-1 (RFC 3174) — required by HIBP API
// ─────────────────────────────────────────────

fn sha1(data: &[u8]) -> [u8; 20] {
    use std::num::Wrapping;

    let mut h: [Wrapping<u32>; 5] = [
        Wrapping(0x67452301u32),
        Wrapping(0xEFCDAB89u32),
        Wrapping(0x98BADCFEu32),
        Wrapping(0x10325476u32),
        Wrapping(0xC3D2E1F0u32),
    ];

    // Pre-processing: pad to 512-bit boundary
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) chunk
    for chunk in msg.chunks(64) {
        let mut w = [Wrapping(0u32); 80];
        for i in 0..16 {
            w[i] = Wrapping(u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]));
        }
        for i in 16..80 {
            let val = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).0;
            w[i] = Wrapping(val.rotate_left(1));
        }

        let [mut a, mut b, mut c, mut d, mut e] = h;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19  => ((b & c) | (!b & d), Wrapping(0x5A827999u32)),
                20..=39 => (b ^ c ^ d,           Wrapping(0x6ED9EBA1u32)),
                40..=59 => ((b & c) | (b & d) | (c & d), Wrapping(0x8F1BBCDCu32)),
                _       => (b ^ c ^ d,           Wrapping(0xCA62C1D6u32)),
            };
            let temp = Wrapping(a.0.rotate_left(5))
                + f + e + k + w[i];
            e = d;
            d = c;
            c = Wrapping(b.0.rotate_left(30));
            b = a;
            a = temp;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.0.to_be_bytes());
    }
    out
}
