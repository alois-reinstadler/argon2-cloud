import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { validator } from 'hono/validator';
import { serve } from '@hono/node-server';
import { hash, verify } from '@node-rs/argon2';
const app = new Hono();
const port = parseInt(`${process.env.PORT || 8080}`);
const argonOptions = {
    // recommended minimum parameters
    memoryCost: 19456, // ~ 20MB
    timeCost: 2,
    outputLen: 32,
    parallelism: 1,
};
const api = app.use("/api", cors({ origin: ["https://alrein.dev", "https://postkorb.app"] }));
api.post("/hash", validator("form", (value, c) => {
    const password = value["password"];
    if (!password ||
        typeof password !== "string" ||
        password.length < 8 ||
        password.length > 64) {
        return c.text("Bad Request", 400);
    }
    return { password };
}), async (c) => {
    const { password } = c.req.valid("form");
    const hashed = await hash(password, argonOptions);
    return c.json({
        hash: hashed,
    });
});
api.post("/verify", validator("form", (value, c) => {
    const password = value["password"];
    const hash = value["hash"];
    if (!validatePassword(password) || !validateHash(hash)) {
        return c.text("Bad Request", 400);
    }
    return { password, hash };
}), async (c) => {
    const { password, hash } = c.req.valid("form");
    const matches = await verify(hash, password, argonOptions);
    return c.json({ matches });
});
serve({
    fetch: app.fetch,
    port,
});
// utils
function validatePassword(value) {
    if (Array.isArray(value))
        value = value[0];
    return Boolean(value && typeof value === "string" && value.length > 8 && value.length <= 64);
}
function validateHash(value) {
    if (Array.isArray(value))
        value = value[0];
    return Boolean(value && typeof value === "string" && value.length > 4);
}
