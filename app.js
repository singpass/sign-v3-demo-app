const express = require("express");
const config = require("./config.json");
const { readFileSync } = require("node:fs");
const { SignJWT, importJWK, createRemoteJWKSet, jwtVerify } = require("jose");
const NodeCache = require("node-cache");
const assert = require("node:assert");

const axios = require("axios").create({ baseURL: config.SIGN_BASE_URL });
const cache = new NodeCache({ stdTTL: 5400 });
const app = express();

app.use(express.json());

const createJwt = async (payload) => {
  return new SignJWT(payload)
    .setIssuedAt()
    .setProtectedHeader({
      alg: "ES256",
      kid: config.CLIENT_PRIVATE_KEY.kid,
    })
    .setJti(crypto.randomUUID())
    .setExpirationTime("120s")
    .sign(await importJWK(config.CLIENT_PRIVATE_KEY));
};

app.use(express.static("frontend"));

app.get("/sign", async (req, res) => {
  const payload = {
    x: 0.5,
    y: 0.5,
    page: 1,
    doc_name: "dummy.pdf",
    client_id: config.CLIENT_ID,
  };

  const createSignRequestResponse = await axios
    .post("/sign-requests", readFileSync("dummy.pdf"), {
      headers: {
        "Content-Type": "application/octet-stream",
        Authorization: await createJwt(payload),
      },
    })
    .catch((error) => {
      console.log(error.response.data);
    });

  const { signing_url, request_id, exchange_code } =
    createSignRequestResponse.data;

  cache.set(`exchange_code::${request_id}`, exchange_code);

  return res.redirect(signing_url);
});

app.get("/sign-requests/:request_id", async (req, res) => {
  const { request_id } = req.params;

  const exchange_code = await cache.get(`exchange_code::${request_id}`);
  assert(exchange_code);

  const {
    data: { signed_doc_url },
  } = await axios.get(`/sign-requests/${request_id}/signed_doc`, {
    headers: { Authorization: await createJwt({ exchange_code }) },
  });

  const file = await axios.get(signed_doc_url, { responseType: "stream" });

  res.setHeader(
    "Content-Disposition",
    `attachment; filename="signed_${request_id}.pdf"`,
  );
  res.setHeader("Content-Type", "application/pdf");
  return file.data.pipe(res);
});

app.get("/jwks", (req, res) => {
  const { d, ...publicJwk } = { ...config.CLIENT_PRIVATE_KEY };
  return res.status(200).json({ keys: [publicJwk] });
});

app.post("/webhook", async (req, res) => {
  const token = req.body.token;
  assert(token);

  const { payload } = await jwtVerify(
    token,
    createRemoteJWKSet(new URL(config.SIGN_JWKS_URL)),
  );
  console.log("Webhook received:", payload);
  return res.status(200).send("OK");
});

app.listen(config.PORT, () => {
  console.log(`App started, go to http://localhost:${config.PORT}`);
});
