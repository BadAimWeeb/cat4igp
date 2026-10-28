import { defineConfig } from "vite";
import { createMockApi } from "./dev/mock-api.ts";
// @ts-ignore -- native Node API; no Node typings installed (see dev/mock-api.ts)
import process from "node:process";

const mock = !process.env.CONTROLLER_URL && process.env.MOCK_API !== "0";

export default defineConfig({
  plugins: mock
    ? [
        {
          name: "dev-mock-admin",
          apply: "serve",
          configureServer(server) {
            const api = createMockApi();
            server.middlewares.use(
              (req: Parameters<typeof api.handle>[0], res, next) => {
                if (/^\/admin(?:\/|\?|$)/.test(req.url ?? ""))
                  void api.handle(req, res);
                else next();
              },
            );
          },
        },
      ]
    : [],
  server: {
    // Preserve the browser Origin: the backend must trust the public HTTPS origin.
    proxy: mock
      ? undefined
      : {
          "/admin": {
            target: process.env.CONTROLLER_URL || "http://127.0.0.1:8080",
            changeOrigin: false,
          },
        },
  },
});
