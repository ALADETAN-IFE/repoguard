declare module "js-yaml" {
  export interface DumpOptions {
    indent?: number;
    noArrayIndent?: boolean;
    skipInvalid?: boolean;
    flowLevel?: number;
    styles?: Record<string, unknown>;
    schema?: unknown;
    sortKeys?: boolean | ((a: string, b: string) => number);
    lineWidth?: number;
    noRefs?: boolean;
    noCompatMode?: boolean;
    condenseFlow?: boolean;
    quotingType?: "'" | '"';
    forceQuotes?: boolean;
    replacer?: (key: string, value: unknown) => unknown;
  }

  export function load(input: string, options?: unknown): unknown;
  export function dump(input: unknown, options?: DumpOptions): string;
}
