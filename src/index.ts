import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { validator } from 'hono/validator';

import { serve } from '@hono/node-server';
import { hash, verify } from '@node-rs/argon2';

import type { ParsedFormValue } from "hono/types";
import type { Options as Argon2Options } from "@node-rs/argon2";

const app = new Hono();
const port = parseInt(`${process.env.PORT || 8080}`);

const argonOptions = {
  // recommended minimum parameters
  memoryCost: 19456, // ~ 20MB
  timeCost: 2,
  outputLen: 32,
  parallelism: 1,
} satisfies Argon2Options;

app.use(
  "/*",
  cors()
  // cors({ origin: ["https://alrein.dev", "https://postkorb.app"] })
);

app.post(
  "/hash",
  validator("form", (value, c) => {
    const password = value["password"];

    if (!validatePassword(password)) {
      return c.text("Bad Request", 400);
    }

    return { password };
  }),
  async (c) => {
    const { password } = c.req.valid("form");
    const hashed = await hash(password, argonOptions);

    return c.json({
      hash: hashed,
    });
  }
);

app.post(
  "/hash",
  validator("form", (value, c) => {
    const password = value["password"];

    if (!validatePassword(password)) {
      return c.text("Bad Request", 400);
    }

    return { password };
  }),
  async (c) => {
    const { password } = c.req.valid("form");

    try {
      const hashed = await hash(password, argonOptions);
      return c.json({ hash: hashed });
    } catch (error) {
      return c.text("Bad Request", 400);
    }
  }
);

app.post(
  "/verify",
  validator("form", (value, c) => {
    const password = value["password"];
    const hashed = value["hash"];

    if (!validatePassword(password) || !validateHash(hashed)) {
      return c.text("Bad Request", 400);
    }

    return { password, hashed };
  }),
  async (c) => {
    const { password, hashed } = c.req.valid("form");

    try {
      const matches = await verify(hashed, password, argonOptions);
      return c.json({ matches });
    } catch (error) {
      if (isArgon2Error(error)) return c.json({ matches: false });
      return c.text("Bad Request", 400);
    }
  }
);

serve({
  fetch: app.fetch,
  port,
});

// utils
function validatePassword(
  value: ParsedFormValue | ParsedFormValue[]
): value is string {
  if (Array.isArray(value)) value = value[0];
  return Boolean(
    value && typeof value === "string" && value.length > 8 && value.length <= 64
  );
}

function validateHash(
  value: ParsedFormValue | ParsedFormValue[]
): value is string {
  if (Array.isArray(value)) value = value[0];
  return Boolean(value && typeof value === "string" && value.length > 4);
}

function isArgon2Error(error: unknown): error is Argon2Error {
  return (
    error instanceof Error && "code" in error && error.code === "InvalidArg"
  );
}

interface Argon2Error extends Error {
  code: string;
}
