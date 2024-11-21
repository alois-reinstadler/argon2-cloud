import { Hono } from 'hono';
import { serve } from '@hono/node-server';
const app = new Hono();
const port = parseInt(`${process.env.PORT || 8080}`);
app.get("/", (c) => {
    return c.text("Hello Hono!");
});
console.log(`App listening on port: ${port}`);
serve({
    fetch: app.fetch,
    port,
});
