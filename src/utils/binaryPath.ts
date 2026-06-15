// ─── Helpers ──────────────────────────────────────────────────────────────────

const BINARY_EXTENSIONS = new Set([
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
    ".pdf", ".mp4", ".mp3",
  ]);
  
export function isBinaryPath(filePath: string): boolean {
    return [...BINARY_EXTENSIONS].some((ext) =>
      filePath.toLowerCase().endsWith(ext),
    );
  }