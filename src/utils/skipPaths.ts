// ─── Paths RepoGuard should never scan ───────────────────────────────────────

const SKIP_EXACT = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lockb",
  "npm-shrinkwrap.json",
]);

const SKIP_PATTERNS = [
  /node_modules\//,    
  /^\.git\//,             
  /vendor\//,       

  // Test files
  /\.(test|spec)\.(ts|js|tsx|jsx|py|rb|go)$/i,
  /^tests?\//i,
  /\/__tests__\//i,
  /\/fixtures?\//i,
  /\/mocks?\//i,
  /\/stubs?\//i,

  // Documentation and examples
  /\/examples?\//i,
  /\/docs?\//i,
  /\/tutorials?\//i,
  /\/courses?\//i,
  /\/lessons?\//i,
  /\/exercises?\//i,
  /\/solutions?\//i,
  /\/demos?\//i,
  /\/samples?\//i,

  // RepoGuard's own source — contains patterns as strings
  /^src\/scanner\//i,
  /^src\/pullRequest\//i,

  // Build output
  /^dist\//i,
  /^build\//i,
  /^\.next\//i,
  /^out\//i,
  /^coverage\//i,

  // Generated files
  /\.min\.(js|css)$/i,
  /\.bundle\.js$/i,
  /\.chunk\.js$/i,
];

export function shouldSkipPath(filePath: string): boolean {
  if (SKIP_EXACT.has(filePath)) return true;
  return SKIP_PATTERNS.some((p) => p.test(filePath));
}