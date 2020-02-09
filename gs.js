const sodium = require('tweetsodium');
const axios = require("axios");
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const sendReq = async (tokenValue, verb, path, data) => {
  try {
    const res = await axios({
      url: 'https://api.github.com' + path,
      port: 443,
      path: path,
      method: verb,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
        'Authorization': `token ${tokenValue}`,
        'content-type': 'application/json'
      },
      data: data
    });
    console.log("Status: ", res.status, " data: ", res.data);
    return res;
  } catch (e) {
    console.log(e);
  }
}

const setSecret = async (publicKey, token, username, repo, kv) => {
  const key = publicKey.key;
  const value = kv.value;

// Convert the message and key to Uint8Array's (Buffer implements that interface)
  const messageBytes = Buffer.from(value);
  const keyBytes = Buffer.from(key, 'base64');

// Encrypt using LibSodium.
  const encryptedBytes = sodium.seal(messageBytes, keyBytes);

// Base64 the encrypted secret
  const encrypted = Buffer.from(encryptedBytes).toString('base64');

  const sec = JSON.stringify({
    "key_id": publicKey.key_id,
    "encrypted_value": encrypted
  });

  await sendReq(token, 'PUT', `/repos/${username}/${repo}/actions/secrets/${kv.key}`, sec);
}

const setSecrets = async (token, username, repo, secrets ) => {
  const publicKey = await sendReq(token, 'GET', `/repos/${username}/${repo}/actions/secrets/public-key`, null);

  for (const kv of secrets) {
    setSecret(publicKey.data, token, username, repo, kv);
  }
}


app.post('/:username/:projecturl', async (req, res) => {
  const token = process.env.REPO_TOKEN;
  const username = req.params.username;// 'ateventhorizon';
  const projecturl = req.params.projecturl;
  const repo = projecturl;

  const path='/v2/floating_ips?page=1&per_page=20';
  const dataJSON = await axios({
    url: 'https://api.digitalocean.com' + path,
    port: 443,
    path: path,
    method: "PUT",
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
      'Authorization': `Bearer ${process.env.DO_TOKEN}`,
      'Content-Type': 'application/json'
    },
  });

  let ip = '0.0.0.0';
  for ( const doip of dataJSON.data.floating_ips ) {
    if ( doip.droplet.name === projecturl ) {
      ip = doip.ip;
    }
  }

  const secrets = [
    {key: "DOCKER_HUB_ID", value: process.env.DOCKER_HUB_ID},
    {key: "DOCKER_HUB_TOKEN", value: process.env.DOCKER_HUB_TOKEN},
    {key: "DROPLET_IP", value: ip},
    {key: "DROPLET_USER", value: process.env.DROPLET_USER},
    {key: "EH_CLOUD_HOST", value: projecturl},
    {key: "EH_MONGO_REPLICA_SET_NAME", value: process.env.EH_MONGO_REPLICA_SET_NAME},
    {key: "EH_MONGO_PATH", value: process.env.EH_MONGO_PATH },
    {key: "EH_MONGO_DEFAULT_DB", value: projecturl },
    {key: "MTN_DB_PATH", value: process.env.MTN_DB_PATH },
    {key: "EH_MASTER_TOKEN", value: projecturl+ip+username+repo},
    {key: "SECRET_PRIVATE_DEPLOY_KEY", value: process.env.SECRET_PRIVATE_DEPLOY_KEY},
  ];

  // console.log(dataJSON);
  console.log(secrets);
  setSecrets(token, username, repo, secrets);
  res.send("Hello, world!");
});

app.get('/', (req, res) => {
  res.send( "Follow the white rabbit...");
});

const port = process.env.PORT || 3003;
app.listen(port, async () => {
  console.log('listening on *:' + port);
});
