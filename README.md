# Filesystem MCP Server (HTTP Streaming)

An HTTP streaming port of the official [MCP Filesystem Server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) by Anthropic.

## About This Port

This is a port of [@modelcontextprotocol/server-filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) that replaces the **stdio** transport with **HTTP Streaming** (Streamable HTTP transport).

### Why HTTP Streaming?

The original MCP filesystem server uses stdio transport, which works well for local CLI integrations but has limitations:

- Requires spawning a subprocess for each connection
- Not suitable for remote/networked deployments
- Can't be accessed by web-based MCP clients

This port uses HTTP Streaming, enabling:

- **Remote access** - Connect over HTTP from anywhere
- **Multiple concurrent sessions** - Handle many clients simultaneously
- **Web client compatibility** - Works with browser-based MCP clients
- **Standalone deployment** - Run as a service without subprocess management

All filesystem functionality from the original is preserved.

---

## Features

- Read/write files
- Create/list/delete directories
- Move files/directories
- Search files
- Get file metadata
- Dynamic directory access control via [Roots](https://modelcontextprotocol.io/docs/learn/client-concepts#roots)

## Installation

```bash
npm install -g server-filesystem-http
```

Or for local development:
```bash
npm install
npm run build
```

## Usage

### Quick Start

```bash
# Initialize credentials (creates .env with random values)
npx server-filesystem-http --init

# Start the server with current directory (if safe)
npx server-filesystem-http

# Or specify directories explicitly
npx server-filesystem-http /path/to/dir1 /path/to/dir2
```

The `--init` command generates random `CLIENT_ID` and `CLIENT_SECRET` values and saves them to a `.env` file. The credentials are printed to the console so you can use them in your client.

### Default Directory Behavior

When no directories are specified, the server will serve the **current working directory** if it's considered safe. The server will refuse to auto-serve:
- Root directory (`/`)
- Home directory (`~`)
- System directories (`/usr`, `/etc`, `/var`, `/System`, etc.)

To serve these directories, you must specify them explicitly as command-line arguments.

### Command Line Options

| Option | Description |
|--------|-------------|
| `--init` | Generate random credentials and save to `.env` |
| `--force` | Used with `--init` to overwrite existing `.env` |

### Interactive Mode

If credentials are missing and you're running in an interactive terminal, the server will prompt:

```
Would you like to create .env with random credentials? (y/n):
```

### Environment Variables

You can also provide credentials via environment variables:

```bash
CLIENT_ID=myid CLIENT_SECRET=mysecret npx server-filesystem-http /path/to/dir

# With custom port
PORT=8080 CLIENT_ID=myid CLIENT_SECRET=mysecret npx server-filesystem-http /path/to/dir
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLIENT_ID` | Yes | - | OAuth client ID |
| `CLIENT_SECRET` | Yes | - | OAuth client secret |
| `PORT` | No | 24024 | Server port |

The server exposes endpoints at `http://localhost:24024/`.

### HTTP Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/token` | No | OAuth token endpoint (client credentials grant) |
| POST | `/mcp` | Bearer | Send MCP messages (initialize, tool calls, etc.) |
| GET | `/mcp` | Bearer | SSE stream for server-to-client notifications |
| DELETE | `/mcp` | Bearer | Terminate session |

## Authentication

This server uses OAuth 2.0 Client Credentials flow.

### Step 1: Get Access Token

```bash
curl -X POST http://localhost:24024/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET"
```

Response:
```json
{
  "access_token": "abc123...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Step 2: Use Token for MCP Requests

```bash
# Initialize session
curl -X POST http://localhost:24024/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": { "name": "my-client", "version": "1.0.0" }
    }
  }'

# Use the mcp-session-id header from the response for subsequent requests
```

## Directory Access Control

The server uses a flexible directory access control system. Directories can be specified via command-line arguments or dynamically via [Roots](https://modelcontextprotocol.io/docs/learn/client-concepts#roots).

### Method 1: Command-line Arguments
Specify allowed directories when starting the server:
```bash
node dist/index.js /path/to/dir1 /path/to/dir2
```

### Method 2: MCP Roots (Recommended)
MCP clients that support [Roots](https://modelcontextprotocol.io/docs/learn/client-concepts#roots) can dynamically update the allowed directories.

Roots notified by Client to Server completely replace any server-side allowed directories when provided.

**Important**: If server starts without command-line arguments AND client doesn't support roots protocol (or provides empty roots), the server will throw an error during initialization.

### How It Works

1. **Server Startup** - Server starts with directories from command-line arguments (if provided)
2. **Client Connection** - Client connects and sends `initialize` request with capabilities
3. **Roots Protocol** - If client supports roots, server requests and uses client's roots
4. **Fallback** - If client doesn't support roots, server uses command-line directories only
5. **Access Control** - All filesystem operations are restricted to allowed directories

## API

### Tools

- **read_text_file**
  - Read complete contents of a file as text
  - Inputs:
    - `path` (string)
    - `head` (number, optional): First N lines
    - `tail` (number, optional): Last N lines
  - Always treats the file as UTF-8 text regardless of extension
  - Cannot specify both `head` and `tail` simultaneously

- **read_media_file**
  - Read an image or audio file
  - Inputs:
    - `path` (string)
  - Streams the file and returns base64 data with the corresponding MIME type

- **read_multiple_files**
  - Read multiple files simultaneously
  - Input: `paths` (string[])
  - Failed reads won't stop the entire operation

- **write_file**
  - Create new file or overwrite existing (exercise caution with this)
  - Inputs:
    - `path` (string): File location
    - `content` (string): File content

- **edit_file**
  - Make selective edits using advanced pattern matching and formatting
  - Features:
    - Line-based and multi-line content matching
    - Whitespace normalization with indentation preservation
    - Multiple simultaneous edits with correct positioning
    - Indentation style detection and preservation
    - Git-style diff output with context
    - Preview changes with dry run mode
  - Inputs:
    - `path` (string): File to edit
    - `edits` (array): List of edit operations
      - `oldText` (string): Text to search for (can be substring)
      - `newText` (string): Text to replace with
    - `dryRun` (boolean): Preview changes without applying (default: false)
  - Returns detailed diff and match information for dry runs, otherwise applies changes
  - Best Practice: Always use dryRun first to preview changes before applying them

- **create_directory**
  - Create new directory or ensure it exists
  - Input: `path` (string)
  - Creates parent directories if needed
  - Succeeds silently if directory exists

- **list_directory**
  - List directory contents with [FILE] or [DIR] prefixes
  - Input: `path` (string)

- **list_directory_with_sizes**
  - List directory contents with [FILE] or [DIR] prefixes, including file sizes
  - Inputs:
    - `path` (string): Directory path to list
    - `sortBy` (string, optional): Sort entries by "name" or "size" (default: "name")
  - Returns detailed listing with file sizes and summary statistics
  - Shows total files, directories, and combined size

- **move_file**
  - Move or rename files and directories
  - Inputs:
    - `source` (string)
    - `destination` (string)
  - Fails if destination exists

- **search_files**
  - Recursively search for files/directories that match or do not match patterns
  - Inputs:
    - `path` (string): Starting directory
    - `pattern` (string): Search pattern
    - `excludePatterns` (string[]): Exclude any patterns.
  - Glob-style pattern matching
  - Returns full paths to matches

- **directory_tree**
  - Get recursive JSON tree structure of directory contents
  - Inputs:
    - `path` (string): Starting directory
    - `excludePatterns` (string[]): Exclude any patterns. Glob formats are supported.
  - Returns:
    - JSON array where each entry contains:
      - `name` (string): File/directory name
      - `type` ('file'|'directory'): Entry type
      - `children` (array): Present only for directories
        - Empty array for empty directories
        - Omitted for files
  - Output is formatted with 2-space indentation for readability

- **get_file_info**
  - Get detailed file/directory metadata
  - Input: `path` (string)
  - Returns:
    - Size
    - Creation time
    - Modified time
    - Access time
    - Type (file/directory)
    - Permissions

- **list_allowed_directories**
  - List all directories the server is allowed to access
  - No input required
  - Returns:
    - Directories that this server can read/write from

### Tool annotations (MCP hints)

This server sets [MCP ToolAnnotations](https://modelcontextprotocol.io/specification/2025-03-26/server/tools#toolannotations)
on each tool so clients can:

- Distinguish **read‑only** tools from write‑capable tools.
- Understand which write operations are **idempotent** (safe to retry with the same arguments).
- Highlight operations that may be **destructive** (overwriting or heavily mutating data).

The mapping for filesystem tools is:

| Tool                        | readOnlyHint | idempotentHint | destructiveHint | Notes                                            |
|-----------------------------|--------------|----------------|-----------------|--------------------------------------------------|
| `read_text_file`            | `true`       | –              | –               | Pure read                                       |
| `read_media_file`           | `true`       | –              | –               | Pure read                                       |
| `read_multiple_files`       | `true`       | –              | –               | Pure read                                       |
| `list_directory`            | `true`       | –              | –               | Pure read                                       |
| `list_directory_with_sizes` | `true`       | –              | –               | Pure read                                       |
| `directory_tree`            | `true`       | –              | –               | Pure read                                       |
| `search_files`              | `true`       | –              | –               | Pure read                                       |
| `get_file_info`             | `true`       | –              | –               | Pure read                                       |
| `list_allowed_directories`  | `true`       | –              | –               | Pure read                                       |
| `create_directory`          | `false`      | `true`         | `false`         | Re‑creating the same dir is a no‑op             |
| `write_file`                | `false`      | `true`         | `true`          | Overwrites existing files                       |
| `edit_file`                 | `false`      | `false`        | `true`          | Re‑applying edits can fail or double‑apply      |
| `move_file`                 | `false`      | `false`        | `false`         | Move/rename only; repeat usually errors         |

## Security

- **OAuth 2.0 authentication** - All MCP endpoints require a valid Bearer token
- Only directories specified at startup (or via MCP Roots) are accessible
- CORS is permissive (`*`) - restrict in production via reverse proxy

## License

This MCP server is licensed under the MIT License. This means you are free to use, modify, and distribute the software, subject to the terms and conditions of the MIT License. For more details, please see the LICENSE file in the project repository.

## Credits

Based on the [MCP Filesystem Server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) by Anthropic, PBC.
