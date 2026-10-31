// Prints an scrypt hash of an owner passcode for RFAI_MCP_OWNER_PASSCODE_HASH.
// The passcode is read from the terminal without echo (or from stdin when piped) and is
// never printed or written anywhere. Only the hash is printed.
//
// Run: node scripts/hash-passcode.mjs
import { randomBytes, scryptSync } from "node:crypto";
import { stdin, stdout, stderr } from "node:process";

const N = 1 << 15, r = 8, p = 1, KEYLEN = 32;

function readHidden(prompt) {
  return new Promise((resolve) => {
    if (!stdin.isTTY) {
      let data = "";
      stdin.setEncoding("utf8");
      stdin.on("data", (c) => (data += c));
      stdin.on("end", () => resolve(data.replace(/\r?\n$/, "")));
      return;
    }
    stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let value = "";
    const onData = (ch) => {
      if (ch === "\r" || ch === "\n" || ch === "\u0004") {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.off("data", onData);
        stderr.write("\n");
        resolve(value);
      } else if (ch === "\u0003") {
        process.exit(130);
      } else if (ch === "\u007f") {
        value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

const pass = await readHidden("Owner passcode (at least 12 characters): ");
if (pass.length < 12) {
  stderr.write("Passcode must be at least 12 characters.\n");
  process.exit(1);
}
if (stdin.isTTY) {
  const again = await readHidden("Repeat it: ");
  if (again !== pass) {
    stderr.write("The two entries differ.\n");
    process.exit(1);
  }
}
const salt = randomBytes(16);
const hash = scryptSync(pass, salt, KEYLEN, { N, r, p, maxmem: 128 * N * r * 2 });
stdout.write(`scrypt$${N}$${r}$${p}$${salt.toString("base64url")}$${hash.toString("base64url")}\n`);
