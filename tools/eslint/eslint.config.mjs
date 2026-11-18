// Minimal flat config for security linting only (ESLint 9).
// Style rules are off; only eslint-plugin-security's recommended rules run.
import security from "eslint-plugin-security";
import tseslint from "typescript-eslint";

export default [
  {
    ignores: [
      "**/node_modules/**", "**/dist/**", "**/build/**", "**/coverage/**",
      "**/*.min.js", "**/vendor/**", "**/.git/**",
    ],
  },
  {
    files: ["**/*.{js,cjs,mjs,jsx}"],
    languageOptions: { ecmaVersion: "latest", sourceType: "module" },
    linterOptions: { reportUnusedDisableDirectives: "off", noInlineConfig: true },
    ...security.configs.recommended,
  },
  {
    files: ["**/*.{ts,tsx,mts,cts}"],
    languageOptions: { parser: tseslint.parser, ecmaVersion: "latest", sourceType: "module" },
    linterOptions: { reportUnusedDisableDirectives: "off", noInlineConfig: true },
    ...security.configs.recommended,
  },
];
