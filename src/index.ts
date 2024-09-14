import app from "./app.ts";

app.listen(process.env.EXPRESS_PORT, () => {
    console.log(`listening on ${process.env.EXPRESS_DOMAIN}:${process.env.EXPRESS_PORT}`);
});