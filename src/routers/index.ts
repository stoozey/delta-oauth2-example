import { Router, Request, Response, NextFunction } from "express";
import { Issuer, Client, TokenSet, generators, custom } from "openid-client";

const router = Router();

// Environment variables
const port = process.env.EXPRESS_PORT;
const clientId = process.env.ROBLOX_OAUTH_CLIENT_ID;
const clientSecret = process.env.ROBLOX_OAUTH_CLIENT_SECRET;

// Secure cookie configuration
const secureCookieConfig = {
    secure: true,
    httpOnly: true,
    signed: true,
};

// OpenID Client
let client: Client;

// Initialize OpenID Client
async function initializeClient() {
    const issuer = await Issuer.discover(
        "https://apis.roblox.com/oauth/.well-known/openid-configuration"
    );

    client = new issuer.Client({
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris: [`http://localhost:${port}/oauth/callback`],
        response_types: ["code"],
        scope: "openid profile universe-messaging-service:publish",
        id_token_signed_response_alg: "ES256",
    });

    // Set clock tolerance
    client[custom.clock_tolerance] = 180;
}

initializeClient().catch(console.error);

// Middleware to check if user is logged in
async function checkLoggedIn(req: Request, res: Response, next: NextFunction) {
    if (req.signedCookies.tokenSet) {
        let tokenSet = new TokenSet(req.signedCookies.tokenSet);

        // Refresh token if expired
        if (tokenSet.expired()) {
            tokenSet = await client.refresh(tokenSet);
            res.cookie("tokenSet", tokenSet, secureCookieConfig);
        }

        next();
    } else {
        res.redirect("/login");
    }
}

// Root route
router.get("/", checkLoggedIn, (req: Request, res: Response) => {
    res.redirect("/home");
});

// Login route
router.get("/login", (req: Request, res: Response) => {
    const state = generators.state();
    const nonce = generators.nonce();

    res
        .cookie("state", state, secureCookieConfig)
        .cookie("nonce", nonce, secureCookieConfig)
        .redirect(
            client.authorizationUrl({
                scope: client.scope as string,
                state,
                nonce,
            })
        );
});

// Logout route
router.get("/logout", async (req: Request, res: Response) => {
    if (req.signedCookies.tokenSet) {
        client.revoke(req.signedCookies.tokenSet.refresh_token);
    }
    res.clearCookie("tokenSet").redirect("/");
});

// OAuth callback route
router.get("/oauth/callback", async (req: Request, res: Response) => {
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(
        `http://localhost:${port}/oauth/callback`,
        params,
        {
            state: req.signedCookies.state,
            nonce: req.signedCookies.nonce,
        }
    );

    res
        .cookie("tokenSet", tokenSet, secureCookieConfig)
        .clearCookie("state")
        .clearCookie("nonce")
        .redirect("/home");
});

// Home route
router.get("/home", checkLoggedIn, (req: Request, res: Response) => {
    const tokenSet = new TokenSet(req.signedCookies.tokenSet);
    res.render("index", { user: tokenSet.claims() });
});

// Message sending route
router.post("/message", checkLoggedIn, async (req: Request, res: Response) => {
    const message = req.body.message;
    const apiUrl = `https://apis.roblox.com/messaging-service/v1/universes/${req.body.universeId}/topics/${req.body.topic}`;

    try {
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

export default router;
