/**
 * This sample is intended to be used in the context of a privately hosted application server,
 * so it is able to securely use a client secret for authorization.
 *
 * For client-side code, PKCE protocol should be used instead of a client secret
 * in order to avoid sharing the client secret publicly.
 */

import express from "express";
import { Issuer, TokenSet, custom, generators } from "openid-client";
import { getHomeHtml } from "./getHomeHtml.js";
import cookieParser from "cookie-parser";

const app = express();
const port = process.env.ROBLOX_PORT || 3000;
const clientId = process.env.ROBLOX_CLIENT_ID;
const clientSecret = process.env.ROBLOX_CLIENT_SECRET;

// Generating a new secret at runtime invalidates existing cookies if the server restarts.
// Set your own constant cookie secret if you want to keep them alive despite server restarting.
const cookieSecret = process.env.COOKIE_SECRET || generators.random();
const secureCookieConfig = {
    secure: true,
    httpOnly: true,
    signed: true,
};

// Middleware to simplify interacting with cookies
app.use(cookieParser(cookieSecret));

// Middleware to parse data from HTML forms
app.use(express.urlencoded({ extended: true }));

async function main() {
    // Ingest the OpenID Connect configuration from the discovery document endpoint
    const issuer = await Issuer.discover(
        "https://apis.roblox.com/oauth/.well-known/openid-configuration"
    );

    const client = new issuer.Client({
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris: [`http://localhost:${port}/oauth/callback`],
        response_types: ["code"],
        scope: "openid profile universe-messaging-service:publish",
        id_token_signed_response_alg: "ES256",
    });

    client[custom.clock_tolerance] = 180;

    // Middleware to ensure user is logged in, refreshes tokens if needed
    async function checkLoggedIn(req, res, next) {
        if (req.signedCookies.tokenSet) {
            // User is logged in. Refresh tokens if expired
            let tokenSet = new TokenSet(req.signedCookies.tokenSet);

            if (tokenSet.expired()) {
                tokenSet = await client.refresh(tokenSet);
                res.cookie("tokenSet", tokenSet, secureCookieConfig);
            }

            next();
        } else {
            // User is not logged in. Redirect to login page.
            res.redirect("/login");
        }
    }

    // Routes
    app.get("/", checkLoggedIn, (req, res) => {
        res.redirect("/home");
    });

    app.get("/login", (req, res) => {
        const state = generators.state();
        const nonce = generators.nonce();

        res
            .cookie("state", state, secureCookieConfig)
            .cookie("nonce", nonce, secureCookieConfig)
            .redirect(
                client.authorizationUrl({
                    scope: client.scope,
                    state,
                    nonce,
                })
            );
    });

    app.get("/logout", async (req, res) => {
        // Revoke the session tokens if available
        if (req.signedCookies.tokenSet) {
            client.revoke(req.signedCookies.tokenSet.refresh_token);
        }

        // Clear cookies and redirect back to index (which will lead back to login)
        res.clearCookie("tokenSet").redirect("/");
    });

    app.get("/oauth/callback", async (req, res) => {
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            `http://localhost:${port}/oauth/callback`,
            params,
            {
                state: req.signedCookies.state,
                nonce: req.signedCookies.nonce,
            }
        );

        // Store user details in the userData and session tokens in their respective cookies
        res
            .cookie("tokenSet", tokenSet, secureCookieConfig)
            .clearCookie("state")
            .clearCookie("nonce")
            .redirect("/home");
    });

    app.get("/home", checkLoggedIn, (req, res) => {
        const tokenSet = new TokenSet(req.signedCookies.tokenSet);

        // Construct the HTML response with user information from the token claims
        res.send(getHomeHtml(tokenSet.claims()));
    });

    app.post("/message", checkLoggedIn, async (req, res) => {
        const message = req.body.message;
        const apiUrl = `https://apis.roblox.com/messaging-service/v1/universes/${req.body.universeId}/topics/${req.body.topic}`;

        try {
            // Send the message using the access token for authorization
            const result = await client.requestResource(
                apiUrl,
                req.signedCookies.tokenSet.access_token,
                {
                    method: "POST",
                    body: JSON.stringify({ message }),
                    headers: {
                        "Content-Type": "application/json",
                    },
                }
            );
            console.log(result);
            res.sendStatus(result.statusCode);
        } catch (error) {
            console.error(error);
            res.sendStatus(500);
        }
    });

    // Start the server
    app.listen(port, () => {
        console.log(`Server is running on port: ${port}`);
    });
}

main().catch(console.error);
