import js from "@eslint/js";
import typescript from "typescript-eslint";
import globals from "globals";

export default typescript.config(
  js.configs.recommended,
  ...typescript.configs.strict,

  // TypeScript files
  {
    files: ["**/*.ts"],
    languageOptions: {
      globals: globals.node,
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
      "@typescript-eslint/consistent-type-definitions": ["error", "type"],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "no-console": "error",
    },
  },

  // JS config files
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: {
      globals: globals.node,
    },
  },

  // Ignores
  {
    ignores: ["node_modules/**", "dist/**"],
  }
);
