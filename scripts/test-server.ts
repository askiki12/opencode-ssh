import { generateKeyPairSync } from "node:crypto";
import ssh2 from "ssh2";

const { Server } = ssh2;
const port = Number(process.env.SSH_TEST_PORT ?? 2222);
const username = process.env.SSH_TEST_USER ?? "tester";
const password = process.env.SSH_TEST_PASSWORD ?? "secret";

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const hostKey = privateKey.export({ type: "pkcs1", format: "pem" }).toString();

const server = new Server({ hostKeys: [hostKey] }, (client) => {
  client.on("error", () => undefined);
  client.on("authentication", (context) => {
    if (
      context.method === "password" &&
      context.username === username &&
      context.password === password
    ) {
      context.accept();
      return;
    }
    context.reject(["password"]);
  });
  client.on("ready", () => {
    client.on("session", (accept) => {
      const session = accept();
      session.on("pty", (acceptPty) => acceptPty());
      session.on("exec", (acceptExec, _reject, info) => {
        const stream = acceptExec();
        stream.write(`command=${info.command}\n`);
        stream.stderr.write(`stderr=${info.command}\n`);
        stream.exit(0);
        stream.end();
        stream.close();
      });
    });
  });
});

server.listen(port, "127.0.0.1", () => {
  console.log(`test ssh server listening on 127.0.0.1:${port}`);
  console.log(`user=${username} password=${password}`);
});

process.on("SIGINT", () => {
  server.close(() => process.exit(0));
});
