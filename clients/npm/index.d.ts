// Type definitions for the banbo npm wrapper.
// These mirror the JSON contract emitted by `banbo ... -o json`.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Layer = 'dns' | 'network' | 'transport' | 'application' | 'code';

/** A single security finding. */
export interface Finding {
  id: string;
  title: string;
  layer: Layer;
  severity: Severity;
  asset: string;
  evidence?: string;
  description?: string;
  remediation?: string;
  references?: string[];
  cvss?: number;
  compliance?: string[];
  ai_explanation?: string;
  ai_remediation?: string;
  business_impact?: string;
}

/** Severity tallies for a scan. */
export interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

/** A non-fatal error reported by an individual scan module. */
export interface ModuleError {
  module: string;
  error: string;
}

/** The full parsed result of a scan or code review. */
export interface ScanResult {
  target: string;
  host: string;
  started_at: string;
  duration_ms: number;
  findings: Finding[];
  summary: Counts;
  errors?: ModuleError[];
}

/** Options shared by every runner. */
export interface RunOptions {
  /** Working directory for the child process. */
  cwd?: string;
  /** Extra environment variables merged over process.env. */
  env?: NodeJS.ProcessEnv;
  /** Anthropic API key, injected as ANTHROPIC_API_KEY for the child process. */
  anthropicApiKey?: string;
  /** OpenAI API key, injected as OPENAI_API_KEY for the child process. */
  openaiApiKey?: string;
  /** Kill the process after this many milliseconds and reject. */
  timeoutMs?: number;
}

/** Options for `scan`. */
export interface ScanOptions extends RunOptions {
  /** Pass --i-am-authorized; required before active scanning. */
  authorized?: boolean;
  /** Ports to probe, e.g. [80, 443] or "80,443". */
  ports?: Array<number | string> | string;
  /** Per-module timeout understood by banbo, e.g. "5s". */
  timeout?: string;
  /** Enable active (intrusive) checks. */
  active?: boolean;
  /** Disable AI enrichment of findings. */
  noAi?: boolean;
}

/** Options for `code`. */
export interface CodeOptions extends RunOptions {
  /** Run the full (deeper) code review. */
  full?: boolean;
  /** Disable AI enrichment of findings. */
  noAi?: boolean;
}

/** The raw result of running the binary. */
export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

/**
 * Run the banbo binary with raw arguments. Resolves even when banbo exits 1 or 2
 * (findings present); use the exitCode to branch.
 */
export function run(args: string[], opts?: RunOptions): Promise<RunResult>;

/** Run `banbo scan <target> -o json` and return the parsed result. */
export function scan(target: string, opts?: ScanOptions): Promise<ScanResult>;

/** Run `banbo code [path] -o json` and return the parsed result. */
export function code(path?: string, opts?: CodeOptions): Promise<ScanResult>;

/** Run `banbo version` and return the trimmed version string. */
export function version(opts?: RunOptions): Promise<string>;

/** Exit codes treated as a successful run (0 clean/info, 1 low/medium, 2 high/critical). */
export const OK_EXIT_CODES: Set<number>;
