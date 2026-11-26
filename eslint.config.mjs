import tsPlugin from "@typescript-eslint/eslint-plugin";
// REMOVED BY REPOGUARD: createRequire import for malware

// REMOVED BY REPOGUARD: require definition for malware

export default [
  {
    ignores: ["dist/**", "coverage/**", "node_modules/**"],
  },
  ...tsPlugin.configs["flat/recommended-type-checked"],
  {
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/explicit-function-return-type": "warn",
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
];
// REMOVED BY REPOGUARD: obfuscated malware payload
