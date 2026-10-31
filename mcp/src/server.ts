// Entry point: node src/server.ts (Node 22.18+ or 24, which run TypeScript directly).
import { loadConfig, ConfigError } from "./config.ts";
import { createApp } from "./app.ts";

let config;
try {
  config = loadConfig();
} catch (e) {
  if (e instanceof ConfigError) {
    console.error(e.message);
    process.exit(1);
  }
  throw e;
}

const { app } = createApp(config);
const server = app.listen(config.port, () => {
  console.log(`RFAI Council MCP server listening on port ${config.port}; MCP endpoint ${config.resource.href}; backend ${config.backend}`);
  if (config.backend === "embedded" && !process.env.RFAI_LLM_KEY) {
    console.log("Warning: RFAI_LLM_KEY is not set. council_screen and council_info work; council_ask will refuse or fail before any model call.");
  }
});
for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => server.close(() => process.exit(0)));
