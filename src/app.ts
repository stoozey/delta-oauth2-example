import express, { Express } from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";

import "./config/env.ts";

import cwd from "./config/cwd.ts";
import { isDevelopment, isProduction } from "./config/env.ts";

//// app
const app = express();

// npm middleware
app.set("view engine", "ejs");
app.set("views", `${cwd}/views`);
app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          ...helmet.contentSecurityPolicy.getDefaultDirectives(),
          "img-src": ["'self'", "*.rbxcdn.com"],
          "script-src": ["'self'", "*.rbxcdn.com"],
          "style-src": ["'self'", "*.rbxcdn.com", "'unsafe-inline'"],
          "font-src": ["'self'", "*.rbxcdn.com"],
        },
      },
      crossOriginEmbedderPolicy: {
        policy: "credentialless",
      },
    })
  );

app.use(express.urlencoded({ extended: true }));

const cookieSecret = process.env.EXPRESS_COOKIE_SECRET
app.use(cookieParser(cookieSecret));

app.use(async (req, res, next) => {
    const locals = res.locals;
    locals.isProduction = isProduction;
    locals.isDevelopment = isDevelopment;

    next();
});

// routers
import index from "./routers/index.ts"
app.use(index);

export default app;