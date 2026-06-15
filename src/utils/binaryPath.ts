// ─── Helpers ──────────────────────────────────────────────────────────────────

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot", 
  ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
  ".pdf", ".mp4", ".mp3",
]);

// ── Detects JS malware hidden inside binary-named files ──
export function looksLikeJavaScript(content: string): boolean {
  return (
    /global\[['"]!['"]\]/.test(content) ||
    /var _\$_\w+\s*=\s*\(?function/.test(content) ||
    /eval\s*\(/.test(content) ||
    /String\.fromCharCode/.test(content)
  );
}

export function isBinaryPath(filePath: string): boolean {
  return [...BINARY_EXTENSIONS].some((ext) =>
    filePath.toLowerCase().endsWith(ext),
  );
}