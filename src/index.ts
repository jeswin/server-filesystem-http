#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { InMemoryEventStore } from "@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js";
import {
  CallToolResult,
  RootsListChangedNotificationSchema,
  type Root,
} from "@modelcontextprotocol/sdk/types.js";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import fs from "fs/promises";
import { createReadStream, existsSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import readline from "readline";
import { z } from "zod";
import { minimatch } from "minimatch";
import { normalizePath, expandHome } from './path-utils.js';
import { getValidRootDirectories } from './roots-utils.js';
import {
  // Function imports
  formatSize,
  validatePath,
  getFileStats,
  readFileContent,
  writeFileContent,
  searchFilesWithValidation,
  applyFileEdits,
  tailFile,
  headFile,
  setAllowedDirectories,
} from './lib.js';

// Get the directory where this script is located
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const envPath = path.join(projectRoot, '.env');

// Generate random credentials
function generateRandomCredentials(): { clientId: string; clientSecret: string } {
  return {
    clientId: randomBytes(16).toString('hex'),
    clientSecret: randomBytes(32).toString('hex'),
  };
}

// Create .env file with random credentials
async function createEnvFile(): Promise<{ clientId: string; clientSecret: string }> {
  const credentials = generateRandomCredentials();
  const envContent = `# OAuth Client Credentials (required)
CLIENT_ID=${credentials.clientId}
CLIENT_SECRET=${credentials.clientSecret}

# Server configuration (optional)
PORT=24024
`;
  await fs.writeFile(envPath, envContent);
  return credentials;
}

// Load .env file manually
async function loadEnvFile(): Promise<void> {
  try {
    const content = await fs.readFile(envPath, 'utf-8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex > 0) {
          const key = trimmed.substring(0, eqIndex);
          const value = trimmed.substring(eqIndex + 1);
          if (!process.env[key]) {
            process.env[key] = value;
          }
        }
      }
    }
  } catch {
    // .env doesn't exist, that's fine
  }
}

// Ask user a yes/no question
async function askYesNo(question: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

// Handle --init flag
const rawArgs = process.argv.slice(2);
const hasInit = rawArgs.includes('--init');
const hasForce = rawArgs.includes('--force');

if (hasInit) {
  if (existsSync(envPath) && !hasForce) {
    console.log('.env file already exists at:', envPath);
    console.log('Use --force to overwrite.');
    process.exit(1);
  }

  const credentials = await createEnvFile();
  console.log('Created .env file with random credentials:\n');
  console.log(`  CLIENT_ID=${credentials.clientId}`);
  console.log(`  CLIENT_SECRET=${credentials.clientSecret}`);
  console.log(`\nFile location: ${envPath}`);
  console.log('\nYou can now start the server with:');
  console.log('  node dist/index.js /path/to/allowed/directory');
  process.exit(0);
}

// Load .env file if it exists
await loadEnvFile();

// Check for credentials, prompt to create if missing
let CLIENT_ID = process.env.CLIENT_ID;
let CLIENT_SECRET = process.env.CLIENT_SECRET;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.log('Missing required environment variables: CLIENT_ID and CLIENT_SECRET\n');

  if (existsSync(envPath)) {
    console.log('.env file exists but CLIENT_ID or CLIENT_SECRET is not set.');
    console.log('Please check your .env file at:', envPath);
    process.exit(1);
  }

  // Check if stdin is a TTY (interactive terminal)
  if (process.stdin.isTTY) {
    const shouldCreate = await askYesNo('Would you like to create .env with random credentials? (y/n): ');

    if (shouldCreate) {
      const credentials = await createEnvFile();
      CLIENT_ID = credentials.clientId;
      CLIENT_SECRET = credentials.clientSecret;

      console.log('\nCreated .env file with random credentials:\n');
      console.log(`  CLIENT_ID=${CLIENT_ID}`);
      console.log(`  CLIENT_SECRET=${CLIENT_SECRET}`);
      console.log(`\nFile location: ${envPath}\n`);
    } else {
      console.log('\nPlease create .env from .env.example or set environment variables.');
      console.log('You can also use: node dist/index.js --init');
      process.exit(1);
    }
  } else {
    console.log('Not running in interactive mode.');
    console.log('Please either:');
    console.log('  1. Run with --init to create .env: node dist/index.js --init');
    console.log('  2. Create .env file manually (see .env.example)');
    console.log('  3. Set CLIENT_ID and CLIENT_SECRET environment variables');
    process.exit(1);
  }
}

// Token storage (in production, use Redis or similar)
const accessTokens: Map<string, { expiresAt: number }> = new Map();

// Token expiration time (1 hour)
const TOKEN_EXPIRATION_MS = 60 * 60 * 1000;

// Generate access token
function generateAccessToken(): string {
  return createHash('sha256')
    .update(randomUUID() + Date.now().toString())
    .digest('hex');
}

// Validate access token
function validateAccessToken(token: string): boolean {
  const tokenData = accessTokens.get(token);
  if (!tokenData) return false;
  if (Date.now() > tokenData.expiresAt) {
    accessTokens.delete(token);
    return false;
  }
  return true;
}

// Auth middleware
function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'unauthorized',
      error_description: 'Missing or invalid Authorization header. Use Bearer token.',
    });
    return;
  }

  const token = authHeader.substring(7);
  if (!validateAccessToken(token)) {
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Access token is invalid or expired.',
    });
    return;
  }

  next();
}

// Command line argument parsing
const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("Usage: mcp-server-filesystem [allowed-directory] [additional-directories...]");
  console.error("Note: Allowed directories can be provided via:");
  console.error("  1. Command-line arguments (shown above)");
  console.error("  2. MCP roots protocol (if client supports it)");
  console.error("At least one directory must be provided by EITHER method for the server to operate.");
}

// Store allowed directories in normalized and resolved form
let allowedDirectories = await Promise.all(
  args.map(async (dir) => {
    const expanded = expandHome(dir);
    const absolute = path.resolve(expanded);
    try {
      // Security: Resolve symlinks in allowed directories during startup
      // This ensures we know the real paths and can validate against them later
      const resolved = await fs.realpath(absolute);
      return normalizePath(resolved);
    } catch (error) {
      // If we can't resolve (doesn't exist), use the normalized absolute path
      // This allows configuring allowed dirs that will be created later
      return normalizePath(absolute);
    }
  })
);

// Validate that all directories exist and are accessible
await Promise.all(allowedDirectories.map(async (dir) => {
  try {
    const stats = await fs.stat(dir);
    if (!stats.isDirectory()) {
      console.error(`Error: ${dir} is not a directory`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`Error accessing directory ${dir}:`, error);
    process.exit(1);
  }
}));

// Initialize the global allowedDirectories in lib.ts
setAllowedDirectories(allowedDirectories);

// Schema definitions
const ReadTextFileArgsSchema = z.object({
  path: z.string(),
  tail: z.number().optional().describe('If provided, returns only the last N lines of the file'),
  head: z.number().optional().describe('If provided, returns only the first N lines of the file')
});

const ReadMediaFileArgsSchema = z.object({
  path: z.string()
});

const ReadMultipleFilesArgsSchema = z.object({
  paths: z
    .array(z.string())
    .min(1, "At least one file path must be provided")
    .describe("Array of file paths to read. Each path must be a string pointing to a valid file within allowed directories."),
});

const WriteFileArgsSchema = z.object({
  path: z.string(),
  content: z.string(),
});

const EditOperation = z.object({
  oldText: z.string().describe('Text to search for - must match exactly'),
  newText: z.string().describe('Text to replace with')
});

const EditFileArgsSchema = z.object({
  path: z.string(),
  edits: z.array(EditOperation),
  dryRun: z.boolean().default(false).describe('Preview changes using git-style diff format')
});

const CreateDirectoryArgsSchema = z.object({
  path: z.string(),
});

const ListDirectoryArgsSchema = z.object({
  path: z.string(),
});

const ListDirectoryWithSizesArgsSchema = z.object({
  path: z.string(),
  sortBy: z.enum(['name', 'size']).optional().default('name').describe('Sort entries by name or size'),
});

const DirectoryTreeArgsSchema = z.object({
  path: z.string(),
  excludePatterns: z.array(z.string()).optional().default([])
});

const MoveFileArgsSchema = z.object({
  source: z.string(),
  destination: z.string(),
});

const SearchFilesArgsSchema = z.object({
  path: z.string(),
  pattern: z.string(),
  excludePatterns: z.array(z.string()).optional().default([])
});

const GetFileInfoArgsSchema = z.object({
  path: z.string(),
});

// Reads a file as a stream of buffers, concatenates them, and then encodes
// the result to a Base64 string. This is a memory-efficient way to handle
// binary data from a stream before the final encoding.
async function readFileAsBase64Stream(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    const chunks: Buffer[] = [];
    stream.on('data', (chunk) => {
      chunks.push(chunk as Buffer);
    });
    stream.on('end', () => {
      const finalBuffer = Buffer.concat(chunks);
      resolve(finalBuffer.toString('base64'));
    });
    stream.on('error', (err) => reject(err));
  });
}

// Factory function to create a new MCP server instance
function createServer() {
  const server = new McpServer(
    {
      name: "secure-filesystem-server",
      version: "0.2.0",
    }
  );

  // Tool registrations

  // read_file (deprecated) and read_text_file
  const readTextFileHandler = async (args: z.infer<typeof ReadTextFileArgsSchema>) => {
    const validPath = await validatePath(args.path);

    if (args.head && args.tail) {
      throw new Error("Cannot specify both head and tail parameters simultaneously");
    }

    let content: string;
    if (args.tail) {
      content = await tailFile(validPath, args.tail);
    } else if (args.head) {
      content = await headFile(validPath, args.head);
    } else {
      content = await readFileContent(validPath);
    }

    return {
      content: [{ type: "text" as const, text: content }],
      structuredContent: { content }
    };
  };

  server.registerTool(
    "read_file",
    {
      title: "Read File (Deprecated)",
      description: "Read the complete contents of a file as text. DEPRECATED: Use read_text_file instead.",
      inputSchema: ReadTextFileArgsSchema.shape,
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    readTextFileHandler
  );

  server.registerTool(
    "read_text_file",
    {
      title: "Read Text File",
      description:
        "Read the complete contents of a file from the file system as text. " +
        "Handles various text encodings and provides detailed error messages " +
        "if the file cannot be read. Use this tool when you need to examine " +
        "the contents of a single file. Use the 'head' parameter to read only " +
        "the first N lines of a file, or the 'tail' parameter to read only " +
        "the last N lines of a file. Operates on the file as text regardless of extension. " +
        "Only works within allowed directories.",
      inputSchema: {
        path: z.string(),
        tail: z.number().optional().describe("If provided, returns only the last N lines of the file"),
        head: z.number().optional().describe("If provided, returns only the first N lines of the file")
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    readTextFileHandler
  );

  server.registerTool(
    "read_media_file",
    {
      title: "Read Media File",
      description:
        "Read an image or audio file. Returns the base64 encoded data and MIME type. " +
        "Only works within allowed directories.",
      inputSchema: {
        path: z.string()
      },
      outputSchema: {
        content: z.array(z.object({
          type: z.enum(["image", "audio", "blob"]),
          data: z.string(),
          mimeType: z.string()
        }))
      },
      annotations: { readOnlyHint: true }
    },
    async (args: z.infer<typeof ReadMediaFileArgsSchema>) => {
      const validPath = await validatePath(args.path);
      const extension = path.extname(validPath).toLowerCase();
      const mimeTypes: Record<string, string> = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
        ".svg": "image/svg+xml",
        ".mp3": "audio/mpeg",
        ".wav": "audio/wav",
        ".ogg": "audio/ogg",
        ".flac": "audio/flac",
      };
      const mimeType = mimeTypes[extension] || "application/octet-stream";
      const data = await readFileAsBase64Stream(validPath);

      const type = mimeType.startsWith("image/")
        ? "image"
        : mimeType.startsWith("audio/")
          ? "audio"
          // Fallback for other binary types, not officially supported by the spec but has been used for some time
          : "blob";
      const contentItem = { type: type as 'image' | 'audio' | 'blob', data, mimeType };
      return {
        content: [contentItem],
        structuredContent: { content: [contentItem] }
      } as unknown as CallToolResult;
    }
  );

  server.registerTool(
    "read_multiple_files",
    {
      title: "Read Multiple Files",
      description:
        "Read the contents of multiple files simultaneously. This is more " +
        "efficient than reading files one by one when you need to analyze " +
        "or compare multiple files. Each file's content is returned with its " +
        "path as a reference. Failed reads for individual files won't stop " +
        "the entire operation. Only works within allowed directories.",
      inputSchema: {
        paths: z.array(z.string())
          .min(1)
          .describe("Array of file paths to read. Each path must be a string pointing to a valid file within allowed directories.")
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    async (args: z.infer<typeof ReadMultipleFilesArgsSchema>) => {
      const results = await Promise.all(
        args.paths.map(async (filePath: string) => {
          try {
            const validPath = await validatePath(filePath);
            const content = await readFileContent(validPath);
            return `${filePath}:\n${content}\n`;
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return `${filePath}: Error - ${errorMessage}`;
          }
        }),
      );
      const text = results.join("\n---\n");
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "write_file",
    {
      title: "Write File",
      description:
        "Create a new file or completely overwrite an existing file with new content. " +
        "Use with caution as it will overwrite existing files without warning. " +
        "Handles text content with proper encoding. Only works within allowed directories.",
      inputSchema: {
        path: z.string(),
        content: z.string()
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: true }
    },
    async (args: z.infer<typeof WriteFileArgsSchema>) => {
      const validPath = await validatePath(args.path);
      await writeFileContent(validPath, args.content);
      const text = `Successfully wrote to ${args.path}`;
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "edit_file",
    {
      title: "Edit File",
      description:
        "Make line-based edits to a text file. Each edit replaces exact line sequences " +
        "with new content. Returns a git-style diff showing the changes made. " +
        "Only works within allowed directories.",
      inputSchema: {
        path: z.string(),
        edits: z.array(z.object({
          oldText: z.string().describe("Text to search for - must match exactly"),
          newText: z.string().describe("Text to replace with")
        })),
        dryRun: z.boolean().default(false).describe("Preview changes using git-style diff format")
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: true }
    },
    async (args: z.infer<typeof EditFileArgsSchema>) => {
      const validPath = await validatePath(args.path);
      const result = await applyFileEdits(validPath, args.edits, args.dryRun);
      return {
        content: [{ type: "text" as const, text: result }],
        structuredContent: { content: result }
      };
    }
  );

  server.registerTool(
    "create_directory",
    {
      title: "Create Directory",
      description:
        "Create a new directory or ensure a directory exists. Can create multiple " +
        "nested directories in one operation. If the directory already exists, " +
        "this operation will succeed silently. Perfect for setting up directory " +
        "structures for projects or ensuring required paths exist. Only works within allowed directories.",
      inputSchema: {
        path: z.string()
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: false }
    },
    async (args: z.infer<typeof CreateDirectoryArgsSchema>) => {
      const validPath = await validatePath(args.path);
      await fs.mkdir(validPath, { recursive: true });
      const text = `Successfully created directory ${args.path}`;
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "list_directory",
    {
      title: "List Directory",
      description:
        "Get a detailed listing of all files and directories in a specified path. " +
        "Results clearly distinguish between files and directories with [FILE] and [DIR] " +
        "prefixes. This tool is essential for understanding directory structure and " +
        "finding specific files within a directory. Only works within allowed directories.",
      inputSchema: {
        path: z.string()
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    async (args: z.infer<typeof ListDirectoryArgsSchema>) => {
      const validPath = await validatePath(args.path);
      const entries = await fs.readdir(validPath, { withFileTypes: true });
      const formatted = entries
        .map((entry) => `${entry.isDirectory() ? "[DIR]" : "[FILE]"} ${entry.name}`)
        .join("\n");
      return {
        content: [{ type: "text" as const, text: formatted }],
        structuredContent: { content: formatted }
      };
    }
  );

  server.registerTool(
    "list_directory_with_sizes",
    {
      title: "List Directory with Sizes",
      description:
        "Get a detailed listing of all files and directories in a specified path, including sizes. " +
        "Results clearly distinguish between files and directories with [FILE] and [DIR] " +
        "prefixes. This tool is useful for understanding directory structure and " +
        "finding specific files within a directory. Only works within allowed directories.",
      inputSchema: {
        path: z.string(),
        sortBy: z.enum(["name", "size"]).optional().default("name").describe("Sort entries by name or size")
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    async (args: z.infer<typeof ListDirectoryWithSizesArgsSchema>) => {
      const validPath = await validatePath(args.path);
      const entries = await fs.readdir(validPath, { withFileTypes: true });

      // Get detailed information for each entry
      const detailedEntries = await Promise.all(
        entries.map(async (entry) => {
          const entryPath = path.join(validPath, entry.name);
          try {
            const stats = await fs.stat(entryPath);
            return {
              name: entry.name,
              isDirectory: entry.isDirectory(),
              size: stats.size,
              mtime: stats.mtime
            };
          } catch (error) {
            return {
              name: entry.name,
              isDirectory: entry.isDirectory(),
              size: 0,
              mtime: new Date(0)
            };
          }
        })
      );

      // Sort entries based on sortBy parameter
      const sortedEntries = [...detailedEntries].sort((a, b) => {
        if (args.sortBy === 'size') {
          return b.size - a.size; // Descending by size
        }
        // Default sort by name
        return a.name.localeCompare(b.name);
      });

      // Format the output
      const formattedEntries = sortedEntries.map(entry =>
        `${entry.isDirectory ? "[DIR]" : "[FILE]"} ${entry.name.padEnd(30)} ${
          entry.isDirectory ? "" : formatSize(entry.size).padStart(10)
        }`
      );

      // Add summary
      const totalFiles = detailedEntries.filter(e => !e.isDirectory).length;
      const totalDirs = detailedEntries.filter(e => e.isDirectory).length;
      const totalSize = detailedEntries.reduce((sum, entry) => sum + (entry.isDirectory ? 0 : entry.size), 0);

      const summary = [
        "",
        `Total: ${totalFiles} files, ${totalDirs} directories`,
        `Combined size: ${formatSize(totalSize)}`
      ];

      const text = [...formattedEntries, ...summary].join("\n");
      const contentBlock = { type: "text" as const, text };
      return {
        content: [contentBlock],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "directory_tree",
    {
      title: "Directory Tree",
      description:
        "Get a recursive tree view of files and directories as a JSON structure. " +
        "Each entry includes 'name', 'type' (file/directory), and 'children' for directories. " +
        "Files have no children array, while directories always have a children array (which may be empty). " +
        "The output is formatted with 2-space indentation for readability. Only works within allowed directories.",
      inputSchema: {
        path: z.string(),
        excludePatterns: z.array(z.string()).optional().default([])
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    async (args: z.infer<typeof DirectoryTreeArgsSchema>) => {
      interface TreeEntry {
        name: string;
        type: 'file' | 'directory';
        children?: TreeEntry[];
      }
      const rootPath = args.path;

      async function buildTree(currentPath: string, excludePatterns: string[] = []): Promise<TreeEntry[]> {
        const validPath = await validatePath(currentPath);
        const entries = await fs.readdir(validPath, { withFileTypes: true });
        const result: TreeEntry[] = [];

        for (const entry of entries) {
          const relativePath = path.relative(rootPath, path.join(currentPath, entry.name));
          const shouldExclude = excludePatterns.some(pattern => {
            if (pattern.includes('*')) {
              return minimatch(relativePath, pattern, { dot: true });
            }
            // For files: match exact name or as part of path
            // For directories: match as directory path
            return minimatch(relativePath, pattern, { dot: true }) ||
              minimatch(relativePath, `**/${pattern}`, { dot: true }) ||
              minimatch(relativePath, `**/${pattern}/**`, { dot: true });
          });
          if (shouldExclude)
            continue;

          const entryData: TreeEntry = {
            name: entry.name,
            type: entry.isDirectory() ? 'directory' : 'file'
          };

          if (entry.isDirectory()) {
            const subPath = path.join(currentPath, entry.name);
            entryData.children = await buildTree(subPath, excludePatterns);
          }

          result.push(entryData);
        }

        return result;
      }

      const treeData = await buildTree(rootPath, args.excludePatterns);
      const text = JSON.stringify(treeData, null, 2);
      const contentBlock = { type: "text" as const, text };
      return {
        content: [contentBlock],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "move_file",
    {
      title: "Move File",
      description:
        "Move or rename files and directories. Can move files between directories " +
        "and rename them in a single operation. If the destination exists, the " +
        "operation will fail. Works across different directories and can be used " +
        "for simple renaming within the same directory. Both source and destination must be within allowed directories.",
      inputSchema: {
        source: z.string(),
        destination: z.string()
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: false }
    },
    async (args: z.infer<typeof MoveFileArgsSchema>) => {
      const validSourcePath = await validatePath(args.source);
      const validDestPath = await validatePath(args.destination);
      await fs.rename(validSourcePath, validDestPath);
      const text = `Successfully moved ${args.source} to ${args.destination}`;
      const contentBlock = { type: "text" as const, text };
      return {
        content: [contentBlock],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "search_files",
    {
      title: "Search Files",
      description:
        "Recursively search for files and directories matching a pattern. " +
        "The patterns should be glob-style patterns that match paths relative to the working directory. " +
        "Use pattern like '*.ext' to match files in current directory, and '**/*.ext' to match files in all subdirectories. " +
        "Returns full paths to all matching items. Great for finding files when you don't know their exact location. " +
        "Only searches within allowed directories.",
      inputSchema: {
        path: z.string(),
        pattern: z.string(),
        excludePatterns: z.array(z.string()).optional().default([])
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    async (args: z.infer<typeof SearchFilesArgsSchema>) => {
      const validPath = await validatePath(args.path);
      const results = await searchFilesWithValidation(validPath, args.pattern, allowedDirectories, { excludePatterns: args.excludePatterns });
      const text = results.length > 0 ? results.join("\n") : "No matches found";
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "get_file_info",
    {
      title: "Get File Info",
      description:
        "Retrieve detailed metadata about a file or directory. Returns comprehensive " +
        "information including size, creation time, last modified time, permissions, " +
        "and type. This tool is perfect for understanding file characteristics " +
        "without reading the actual content. Only works within allowed directories.",
      inputSchema: {
        path: z.string()
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    async (args: z.infer<typeof GetFileInfoArgsSchema>) => {
      const validPath = await validatePath(args.path);
      const info = await getFileStats(validPath);
      const text = Object.entries(info)
        .map(([key, value]) => `${key}: ${value}`)
        .join("\n");
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text }
      };
    }
  );

  server.registerTool(
    "list_allowed_directories",
    {
      title: "List Allowed Directories",
      description:
        "Returns the list of directories that this server is allowed to access. " +
        "Subdirectories within these allowed directories are also accessible. " +
        "Use this to understand which directories and their nested paths are available " +
        "before trying to access files.",
      inputSchema: {},
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true }
    },
    async () => {
      const text = `Allowed directories:\n${allowedDirectories.join('\n')}`;
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text }
      };
    }
  );

  // Updates allowed directories based on MCP client roots
  async function updateAllowedDirectoriesFromRoots(requestedRoots: Root[]) {
    const validatedRootDirs = await getValidRootDirectories(requestedRoots);
    if (validatedRootDirs.length > 0) {
      allowedDirectories = [...validatedRootDirs];
      setAllowedDirectories(allowedDirectories); // Update the global state in lib.ts
      console.error(`Updated allowed directories from MCP roots: ${validatedRootDirs.length} valid directories`);
    } else {
      console.error("No valid root directories provided by client");
    }
  }

  // Handles dynamic roots updates during runtime
  server.server.setNotificationHandler(RootsListChangedNotificationSchema, async () => {
    try {
      const response = await server.server.listRoots();
      if (response && 'roots' in response) {
        await updateAllowedDirectoriesFromRoots(response.roots);
      }
    } catch (error) {
      console.error("Failed to request roots from client:", error instanceof Error ? error.message : String(error));
    }
  });

  // Handles post-initialization setup
  server.server.oninitialized = async () => {
    const clientCapabilities = server.server.getClientCapabilities();

    if (clientCapabilities?.roots) {
      try {
        const response = await server.server.listRoots();
        if (response && 'roots' in response) {
          await updateAllowedDirectoriesFromRoots(response.roots);
        } else {
          console.error("Client returned no roots set, keeping current settings");
        }
      } catch (error) {
        console.error("Failed to request initial roots from client:", error instanceof Error ? error.message : String(error));
      }
    } else {
      if (allowedDirectories.length > 0) {
        console.error("Client does not support MCP Roots, using allowed directories set from server args:", allowedDirectories);
      } else {
        throw new Error(`Server cannot operate: No allowed directories available. Server was started without command-line directories and client either does not support MCP roots protocol or provided empty roots. Please either: 1) Start server with directory arguments, or 2) Use a client that supports MCP roots protocol and provides valid root directories.`);
      }
    }
  };

  return server;
}

// Express app setup
const app = express();
app.use(
  cors({
    origin: "*",
    methods: "GET,POST,DELETE",
    preflightContinue: false,
    optionsSuccessStatus: 204,
    exposedHeaders: ["mcp-session-id", "last-event-id", "mcp-protocol-version"],
  })
);

// OAuth Token Endpoint - Client Credentials Grant
// Uses express.json/urlencoded only for this route
app.post("/token", express.json(), express.urlencoded({ extended: true }), (req: Request, res: Response) => {
  const grantType = req.body.grant_type;
  const clientId = req.body.client_id;
  const clientSecret = req.body.client_secret;

  // Validate grant type
  if (grantType !== 'client_credentials') {
    res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only client_credentials grant type is supported.',
    });
    return;
  }

  // Validate client credentials
  if (clientId !== CLIENT_ID || clientSecret !== CLIENT_SECRET) {
    res.status(401).json({
      error: 'invalid_client',
      error_description: 'Invalid client_id or client_secret.',
    });
    return;
  }

  // Generate and store access token
  const accessToken = generateAccessToken();
  const expiresIn = TOKEN_EXPIRATION_MS / 1000; // in seconds
  accessTokens.set(accessToken, {
    expiresAt: Date.now() + TOKEN_EXPIRATION_MS,
  });

  console.log(`Access token issued for client: ${clientId}`);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
  });
});

// Map sessionId to server transport for each client
const transports: Map<string, StreamableHTTPServerTransport> = new Map();

// Handle POST requests for client messages (protected)
app.post("/mcp", authMiddleware, async (req: Request, res: Response) => {
  console.log("Received MCP POST request");
  try {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports.has(sessionId)) {
      transport = transports.get(sessionId)!;
    } else if (!sessionId) {
      const server = createServer();

      const eventStore = new InMemoryEventStore();
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        eventStore,
        onsessioninitialized: (sessionId: string) => {
          console.log(`Session initialized with ID: ${sessionId}`);
          transports.set(sessionId, transport);
        },
      });

      server.server.onclose = async () => {
        const sid = transport.sessionId;
        if (sid && transports.has(sid)) {
          console.log(`Transport closed for session ${sid}, removing from transports map`);
          transports.delete(sid);
        }
      };

      await server.connect(transport);
      await transport.handleRequest(req, res);
      return;
    } else {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Bad Request: No valid session ID provided",
        },
        id: req?.body?.id,
      });
      return;
    }

    await transport.handleRequest(req, res);
  } catch (error) {
    console.log("Error handling MCP request:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error",
        },
        id: req?.body?.id,
      });
    }
  }
});

// Handle GET requests for SSE streams (protected)
app.get("/mcp", authMiddleware, async (req: Request, res: Response) => {
  console.log("Received MCP GET request");
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Bad Request: No valid session ID provided",
      },
      id: req?.body?.id,
    });
    return;
  }

  const lastEventId = req.headers["last-event-id"] as string | undefined;
  if (lastEventId) {
    console.log(`Client reconnecting with Last-Event-ID: ${lastEventId}`);
  } else {
    console.log(`Establishing new SSE stream for session ${sessionId}`);
  }

  const transport = transports.get(sessionId);
  await transport!.handleRequest(req, res);
});

// Handle DELETE requests for session termination (protected)
app.delete("/mcp", authMiddleware, async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Bad Request: No valid session ID provided",
      },
      id: req?.body?.id,
    });
    return;
  }

  console.log(`Received session termination request for session ${sessionId}`);

  try {
    const transport = transports.get(sessionId);
    await transport!.handleRequest(req, res);
  } catch (error) {
    console.log("Error handling session termination:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Error handling session termination",
        },
        id: req?.body?.id,
      });
    }
  }
});

// Start the server
const PORT = process.env.PORT || 24024;
const httpServer = app.listen(PORT, () => {
  console.error(`MCP Filesystem Server (HTTP Streaming) listening on port ${PORT}`);
  if (allowedDirectories.length === 0) {
    console.error("Started without allowed directories - waiting for client to provide roots via MCP protocol");
  } else {
    console.error(`Allowed directories: ${allowedDirectories.join(", ")}`);
  }
});

// Handle server errors
httpServer.on("error", (err: unknown) => {
  const code =
    typeof err === "object" && err !== null && "code" in err
      ? (err as { code?: unknown }).code
      : undefined;
  if (code === "EADDRINUSE") {
    console.error(`Failed to start: Port ${PORT} is already in use.`);
  } else {
    console.error("HTTP server encountered an error:", err);
  }
  process.exit(1);
});

// Handle server shutdown
process.on("SIGINT", async () => {
  console.log("Shutting down server...");

  for (const [sessionId, transport] of transports) {
    try {
      console.log(`Closing transport for session ${sessionId}`);
      await transport.close();
      transports.delete(sessionId);
    } catch (error) {
      console.log(`Error closing transport for session ${sessionId}:`, error);
    }
  }

  httpServer.close(() => {
    console.log("Server shutdown complete");
    process.exit(0);
  });
});
