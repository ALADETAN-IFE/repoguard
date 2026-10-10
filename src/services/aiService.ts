import logger from "../utils/logger";
import type { Finding } from "../types";

export interface AIAnalysisResult {
  isMalicious: boolean;
  confidence: number; // 0.0 to 1.0
  reasoning: string;
  extractedEndpoints: string[];
  shouldDelete: boolean;
  sanitizedContent?: string;
}

export interface AIPatchResult {
  patchedContent: string;
  shouldDelete: boolean;
  reasoning: string;
  lineSuggestions?: Record<string, string>;
}

/**
 * Checks if an AI provider API key is configured and optionally checks tenant opt-in.
 */
export function isAIEnabled(tenantOptIn = true): boolean {
  if (!tenantOptIn) return false;
  return !!(process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY);
}

/**
 * Privacy Guard: Scrubs API keys, bearer tokens, and secrets from code
 * before sending to LLMs, ensuring zero secret leakage.
 */
export function scrubPotentialSecrets(code: string): string {
  return (
    code
      // GitHub PATs and tokens
      .replace(/gh[pousr]_[A-Za-z0-9_]{36,255}/g, "[SCRUBBED_GITHUB_TOKEN]")
      .replace(/github_pat_[A-Za-z0-9_]{80,255}/g, "[SCRUBBED_GITHUB_PAT]")
      // AWS Access Keys
      .replace(/(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, "[SCRUBBED_AWS_KEY]")
      // Slack tokens
      .replace(/xox[baprs]-[0-9a-zA-Z-]{10,255}/g, "[SCRUBBED_SLACK_TOKEN]")
      // Generic Bearer / API Keys / JWTs
      .replace(
        /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
        "Bearer [SCRUBBED_BEARER_TOKEN]",
      )
      .replace(
        /ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+/g,
        "[SCRUBBED_JWT]",
      )
  );
}

/**
 * Call Gemini Flash REST API with JSON response schema.
 */
async function callGemini(
  prompt: string,
  apiKey: string,
  model?: string,
): Promise<string | null> {
  const preferredModel =
    model || process.env.GEMINI_MODEL || "gemini-2.5-flash";
  const candidateModels = [
    preferredModel,
    "gemini-2.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.8-flash",
    "gemini-2.5-pro",
  ];
  const uniqueCandidates = [...new Set(candidateModels)];

  for (const candidate of uniqueCandidates) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${candidate}:generateContent?key=${apiKey}`;
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ role: "user", parts: [{ text: prompt }] }],
          generationConfig: {
            responseMimeType: "application/json",
            temperature: 0.1,
          },
        }),
        signal: AbortSignal.timeout(12000), // 12s timeout
      });

      if (
        response.status === 404 &&
        candidate !== uniqueCandidates[uniqueCandidates.length - 1]
      ) {
        logger.info(
          `[aiService] Gemini model ${candidate} returned 404 — attempting fallback...`,
        );
        continue;
      }

      if (!response.ok) {
        const errText = await response.text();
        logger.warn(
          `[aiService] Gemini API (${candidate}) returned error ${response.status}: ${errText}`,
        );
        return null;
      }

      const json = (await response.json()) as {
        candidates?: Array<{
          content?: { parts?: Array<{ text?: string }> };
        }>;
      };

      const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
      return text ?? null;
    } catch (err) {
      logger.warn(
        `[aiService] Gemini API call error on ${candidate}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  return null;
}

/**
 * Call OpenAI-compatible REST API (e.g. GPT-4o-mini).
 */
async function callOpenAI(
  prompt: string,
  apiKey: string,
  model?: string,
): Promise<string | null> {
  const chosenModel = model || process.env.OPENAI_MODEL || "gpt-4o-mini";
  const url = "https://api.openai.com/v1/chat/completions";
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: chosenModel,
        messages: [{ role: "user", content: prompt }],
        response_format: { type: "json_object" },
        temperature: 0.1,
      }),
      signal: AbortSignal.timeout(12000),
    });

    if (!response.ok) {
      const errText = await response.text();
      logger.warn(
        `[aiService] OpenAI API (${chosenModel}) returned error ${response.status}: ${errText}`,
      );
      return null;
    }

    const json = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };

    const content = json.choices?.[0]?.message?.content;
    return content ?? null;
  } catch (err) {
    logger.warn(
      `[aiService] OpenAI API call error: ${err instanceof Error ? err.message : String(err)}`,
    );
    return null;
  }
}

/**
 * Generic caller routing with automatic cross-provider fallback.
 * If Gemini fails (429 rate limit, quota, or outage) and OPENAI_API_KEY is set,
 * it seamlessly falls back to OpenAI.
 */
async function queryLLM(prompt: string): Promise<string | null> {
  const geminiKey = process.env.GEMINI_API_KEY;
  const openAIKey = process.env.OPENAI_API_KEY;

  if (geminiKey) {
    const geminiResult = await callGemini(prompt, geminiKey);
    if (geminiResult) return geminiResult;

    if (openAIKey) {
      logger.info(
        "[aiService] Gemini request failed or rate-limited — falling back to OpenAI...",
      );
      const openAIResult = await callOpenAI(prompt, openAIKey);
      if (openAIResult) return openAIResult;
    }
    return null;
  }

  if (openAIKey) {
    return callOpenAI(prompt, openAIKey);
  }

  return null;
}

/**
 * Analyze suspicious/obfuscated code to de-obfuscate intent and determine if it is malware.
 */
export async function analyzeSuspiciousCode(
  code: string,
  filePath: string,
  findings: Finding[] = [],
): Promise<AIAnalysisResult | null> {
  if (!isAIEnabled()) return null;

  try {
    const safeCode = scrubPotentialSecrets(code);
    const prompt = `You are RepoGuard's expert Application Security AI.
Analyze the following code from file "${filePath}" for malicious code, backdoors, obfuscated payloads, credential stealers, data exfiltration, or supply chain tampering.

Static scanner findings for this file:
${JSON.stringify(findings, null, 2)}

Code content to inspect:
\`\`\`
${safeCode.slice(0, 15000)}
\`\`\`

Return a JSON object with this EXACT structure:
{
  "isMalicious": boolean,
  "confidence": number, // between 0.0 and 1.0
  "reasoning": "Clear explanation of what the code does, de-obfuscating any string arrays, hex escapes, or reverse shells",
  "extractedEndpoints": ["list", "of", "IPs/domains/URLs", "found"],
  "shouldDelete": boolean, // true if the entire file is standalone malware with no legitimate project code
  "sanitizedContent": "If shouldDelete is false and code contains legitimate parts with malware injected, provide the sanitized code with only the malicious part removed. If shouldDelete is true, leave empty."
}`;

    const rawResponse = await queryLLM(prompt);
    if (!rawResponse) return null;

    const parsed = JSON.parse(rawResponse) as AIAnalysisResult;
    logger.info(
      `[aiService] Analyzed ${filePath} — isMalicious: ${parsed.isMalicious} (confidence: ${parsed.confidence}, shouldDelete: ${parsed.shouldDelete})`,
    );
    return parsed;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn(`[aiService] Code analysis failed for ${filePath}: ${msg}`);
    return null;
  }
}

/**
 * Surgically generate a clean patch for code containing malware.
 */
export async function generateAIPatch(
  originalContent: string,
  filePath: string,
  findings: Finding[],
): Promise<AIPatchResult | null> {
  if (!isAIEnabled()) return null;

  try {
    const safeContent = scrubPotentialSecrets(originalContent);
    const prompt = `You are RepoGuard's automated remediation engine.
Given the file "${filePath}" and detected security findings, generate a clean, syntax-valid patched version removing ONLY the malicious payloads, obfuscation scaffolding, and harmful scripts, while preserving all legitimate functionality, exports, comments, and structure.

Detected findings:
${JSON.stringify(findings, null, 2)}

Original File:
\`\`\`
${safeContent.slice(0, 20000)}
\`\`\`

Return a JSON object with this EXACT schema:
{
  "shouldDelete": boolean, // true if the file consists entirely of malware/obfuscation scaffolding with zero legitimate code
  "patchedContent": "Clean sanitized source code as a string (or empty if shouldDelete is true)",
  "reasoning": "Brief explanation of the remediation performed",
  "lineSuggestions": {
    "<lineNumber>": "Replacement code line or snippet for this finding line (e.g. replacing hardcoded credentials with process.env.SECRET_NAME)"
  }
}`;

    const rawResponse = await queryLLM(prompt);
    if (!rawResponse) return null;

    const result = JSON.parse(rawResponse) as AIPatchResult;
    return result;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn(
      `[aiService] AI patch generation failed for ${filePath}: ${msg}`,
    );
    return null;
  }
}

/**
 * Generate a security summary for force-pushes and complex multi-file malware attacks.
 */
export async function summarizeForcePushSecurityImpact(
  files: string[],
  findings: Finding[],
): Promise<string | null> {
  if (!isAIEnabled()) return null;

  try {
    const prompt = `You are RepoGuard's security report summarizer.
A force-push or multi-file threat was detected and remediated. Summarize the attack intent and what was fixed in 2-3 concise bullet points.

Modified files:
${JSON.stringify(files)}

Findings:
${JSON.stringify(findings, null, 2)}

Return a JSON object:
{
  "summary": "Markdown-formatted bullet points explaining what happened and how it was sanitized"
}`;

    const rawResponse = await queryLLM(prompt);
    if (!rawResponse) return null;

    const json = JSON.parse(rawResponse) as { summary?: string };
    return json.summary ?? null;
  } catch {
    return null;
  }
}
