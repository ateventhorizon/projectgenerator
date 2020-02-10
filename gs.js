const sodium = require('tweetsodium');
const axios = require("axios");
const express = require('express');
const bodyParser = require('body-parser');
let userData = require("./user_data.js");

const app = express();
app.use(bodyParser.json());

const EHDropletTag = "eh_generated";

const exec = async (req, res, func) => {
  try {
    res.send(await func());
  } catch (e) {
    res.status(500);
    res.send(e);
  }
}

const findDropletID = (droplets, droplet_name) => {
  for (const droplet of droplets) {
    if (droplet.name === droplet_name) {
      return droplet.id;
    }
  }
  throw("Not a valid droplet with that name");
}

const findDropletIDNoThrow = (droplets, droplet_name) => {
  for (const droplet of droplets) {
    if (droplet.name === droplet_name) {
      return droplet.id;
    }
  }
  return null;
}

const getDropletIP = async (name) => {
  const ret = await digitalOceanAPI("GET", "/v2/droplets");
  const droplets = ret.droplets;
  for (const droplet of droplets) {
    if (droplet.name === name) {
      return {ip: droplet.networks.v4[0].ip_address};
    }
  }
  throw "Droplet not found";
}

const digitalOceanAPI = async (verb, path, data = null, ct = 'application/json') => {
  try {
    const ret = await axios({
      url: 'https://api.digitalocean.com' + path,
      port: 443,
      path: path,
      method: verb,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
        'Authorization': `Bearer ${process.env.DO_TOKEN}`,
        'Content-Type': ct
      },
      data: data
    });
    return ret.data;
  } catch (e) {
    throw(e);
  }
}

const gitHubAPI = async (verb, path, data = null, ct = 'application/json') => {
  try {
    const ret = await axios({
      url: 'https://api.github.com' + path,
      port: 443,
      path: path,
      method: verb,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
        'Authorization': `Bearer ${process.env.REPO_TOKEN}`,
        'Accept': '*.*;application/vnd.github.baptiste-preview+json',
        'Content-Type': ct
      },
      data: data
    });
    return ret.data;
  } catch (e) {
    throw(e);
  }
}

const setSecret = async (publicKey, username, repo, kv) => {
  try {
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

    await gitHubAPI('PUT', `/repos/${username}/${repo}/actions/secrets/${kv.key}`, sec);
    return "Adding " + kv.key + "\n";
  } catch (e) {
    throw(e);
  }
}

const setSecrets = async (username, repo, secrets) => {
  try {
    const publicKey = await gitHubAPI('GET', `/repos/${username}/${repo}/actions/secrets/public-key`);

    let secretLog = "";
    for (const kv of secrets) {
      secretLog += await setSecret(publicKey, username, repo, kv);
    }
    return secretLog;
  } catch (e) {
    throw(e);
  }
}


app.post('/secrets/:username/:projecturl', async (req, res) => {

  try {
    const username = req.params.username;
    const projecturl = req.params.projecturl;
    const repo = projecturl;

    const path = '/v2/floating_ips?page=1&per_page=20';
    let dataJSON = await digitalOceanAPI("GET", path);
    const fips = dataJSON.floating_ips;

    // console.log(" IPS: ", dataJSON.data.floating_ips[0].droplet );
    let ip = '0.0.0.0';
    for (const doip of fips) {
      if (doip.droplet && doip.droplet.name === projecturl) {
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
      {key: "EH_MONGO_PATH", value: process.env.EH_MONGO_PATH},
      {key: "EH_MONGO_DEFAULT_DB", value: projecturl},
      {key: "MTN_DB_PATH", value: process.env.MTN_DB_PATH},
      {key: "EH_MASTER_TOKEN", value: projecturl + ip + username + repo},
      {key: "SECRET_PRIVATE_DEPLOY_KEY", value: process.env.SECRET_PRIVATE_DEPLOY_KEY},
    ];

    // console.log(secrets);
    const logs = await setSecrets(username, repo, secrets);
    res.send(logs);
  } catch (e) {
    res.status(500);
    res.send(e);
  }
});

app.get('/domains', async (req, res) => {
  exec(req, res, async () => {
    return await digitalOceanAPI("GET", '/v2/domains');
  });
});

app.get('/dokeys', async (req, res) => {
  exec(req, res, async () => {
    return await digitalOceanAPI("GET", '/v2/account/keys');
  });
});

app.post('/domains/:name', async (req, res) => {
  exec(req, res, async () => {
    // Check if we can assign an IP address from the floating IP droplet
    const ret2 = await digitalOceanAPI("GET", "/v2/floating_ips");
    const fips = ret2.floating_ips;

    let ip = null;
    for (const doip of fips) {
      if (doip.droplet && doip.droplet.name === req.params.name) {
        ip = doip.ip;
      }
    }

    // If no floating IP available, rollback for a normal IP, it has to have one the droplet
    if (ip === null) {
      const ipret = await getDropletIP(req.params.name);
      ip = ipret.ip;
    }

    // Add domain with A record (from ip address)
    await digitalOceanAPI("POST", '/v2/domains',
      {
        name: req.params.name,
        ip_address: ip
      });

    // Add CNAME (extra www for old people like me!)
    return await digitalOceanAPI("POST", `/v2/domains/${req.params.name}/records`,
      {
        "type": "CNAME",
        "name": `www`,
        "data": "@",
        "priority": null,
        "port": null,
        "ttl": 43200,
        "weight": null,
        "flags": null,
        "tag": null
      });
  });
});

app.get('/floatingips', async (req, res) => {
  exec(req, res, async () => {
    return await digitalOceanAPI("GET", "/v2/floating_ips");
  });
});

const findMasterSSHKey = (sshkeys) => {
  for (const key of sshkeys) {
    if (key.name === "ziocleto.pub") {
      return key.id;
    }
  }
  return null;
}

app.get('/droplets', async (req, res) => {
  exec(req, res, async () => {
    return await digitalOceanAPI("GET", "/v2/droplets");
  });
});

app.get('/droplets/ip/:name', async (req, res) => {
  exec(req, res, async () => {
    return await getDropletIP(req.params.name);
  });
});

app.post('/droplets/:name/:username', async (req, res) => {
  exec(req, res, async () => {
    const ks = await digitalOceanAPI("GET", '/v2/account/keys');
    const key = findMasterSSHKey(ks.ssh_keys);
    if (key === null) throw("Cannot find adequate key to map droplet");
    const username = req.params.username;
    const projecturl = req.params.name;

    return await digitalOceanAPI("POST", '/v2/droplets',
      {
        "name": req.params.name,
        "region": "lon1",
        "size": "s-1vcpu-1gb",
        "image": "50944795",
        "ssh_keys": [
          key
        ],
        "backups": false,
        "ipv6": true,
        "user_data": `#!/bin/bash

#
# NameCheap point domains to digital ocean
#
# Digital Ocean: 
# 
#   - Create droplet
#   - Add a domain -> sets A name (and also set CNAME)
#   - run SSL 
#   - Create floating IP, rewrite A name
#   - run GitHub bootstrap 

sudo ufw allow 80
sudo ufw allow 443

curl -X POST https://ehdevops.herokuapp.com/domains/${projecturl}

sudo mkdir -p /docker/letsencrypt-docker-nginx/src/letsencrypt/letsencrypt-site

echo -e "version: '3.1'

services:

  letsencrypt-nginx-container:
    container_name: 'letsencrypt-nginx-container'
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./letsencrypt-site:/usr/share/nginx/html
    networks:
      - docker-network

networks:
  docker-network:
    driver: bridge" | sudo tee /docker/letsencrypt-docker-nginx/src/letsencrypt/docker-compose.yml;

echo -e "server {
    listen 80;
    listen [::]:80;
    server_name doublecanny.com www.${projecturl};

    location ~ /.well-known/acme-challenge {
        allow all;
        root /usr/share/nginx/html;
    }

    root /usr/share/nginx/html;
    index index.html;
}" | sudo tee /docker/letsencrypt-docker-nginx/src/letsencrypt/nginx.conf

echo -e "
<html>
<head>
    <meta charset='utf-8' />
    <title>Let's Encrypt First Time Cert Issue Site</title>
</head>
<body>
    <h1>Oh, hai there!</h1>
    <p>
        This is the temporary site that will only be used for the very first time SSL certificates are issued by Let's Encrypt's
        certbot.
    </p>
</body>
</html>" | sudo tee /docker/letsencrypt-docker-nginx/src/letsencrypt/letsencrypt-site/index.html;

cd /docker/letsencrypt-docker-nginx/src/letsencrypt
sudo docker-compose up -d

sleep 15
docker ps > /dockerps.log
sudo docker run -it --rm -v /docker-volumes/etc/letsencrypt:/etc/letsencrypt -v /docker-volumes/var/lib/letsencrypt:/var/lib/letsencrypt -v /docker/letsencrypt-docker-nginx/src/letsencrypt/letsencrypt-site:/data/letsencrypt -v "/docker-volumes/var/log/letsencrypt:/var/log/letsencrypt" certbot/certbot certonly --webroot --register-unsafely-without-email --agree-tos --webroot-path=/data/letsencrypt --staging -d ${projecturl} -d www.${projecturl} > /sslstaging.log

sudo rm -rf /docker-volumes/

#sudo docker run -it --rm -v /docker-volumes/etc/letsencrypt:/etc/letsencrypt -v /docker-volumes/var/lib/letsencrypt:/var/lib/letsencrypt -v /docker/letsencrypt-docker-nginx/src/letsencrypt/letsencrypt-site:/data/letsencrypt -v "/docker-volumes/var/log/letsencrypt:/var/log/letsencrypt" certbot/certbot certonly --webroot --email messingaroundbigtime@gmail.com --agree-tos --no-eff-email --webroot-path=/data/letsencrypt -d ${projecturl} -d www.${projecturl}

# sudo openssl dhparam -out ~/dhparam-2048.pem 2048

sudo mkdir /sslcerts
sudo cp /docker-volumes/etc/letsencrypt/live/${projecturl}/privkey.pem /sslcerts/
sudo cp /docker-volumes/etc/letsencrypt/live/${projecturl}/fullchain.pem /sslcerts/

# Allocate floating IP and rewrite A records

curl -X POST https://ehdevops.herokuapp.com/floatingips/assign/${projecturl} > /floatingips_assign.log
sleep 10
curl -X PUT https://ehdevops.herokuapp.com/floatingips/domainrecord_a/${projecturl} > /domainrecord_a.log

# boostrap github project

curl -X POST https://ehdevops.herokuapp.com/createrepo/${username}/${projecturl} > /createrepo.log
curl -X POST https://ehdevops.herokuapp.com/secrets/${username}/${projecturl} > /createsecrets.log
`,
        "private_networking": null,
        "volumes": null,
        "tags": [
          EHDropletTag
        ]
      });
  });
});

app.post('/floatingips/assign/:droplet_name', async (req, res) => {
  exec(req, res, async () => {
    const ret = await digitalOceanAPI("GET", `/v2/droplets?tag_name=${EHDropletTag}`);
    const dropletID = findDropletID(ret.droplets, req.params.droplet_name);
    const ret2 = await digitalOceanAPI("GET", "/v2/floating_ips");
    const fips = ret2.floating_ips;

    // Check if we have a free (available) floating IP to assign
    // Will throw if droplet_name has already got a floating ip assigned.
    for (const doip of fips) {
      if (doip.droplet === null) {
        return await digitalOceanAPI("POST", `/v2/floating_ips/${doip.ip}/actions`, {
          "type": "assign",
          "droplet_id": dropletID
        });
      } else if (doip.droplet.name === req.params.droplet_name) {
        throw("IP already assigned to droplet");
      }
    }

    // Create new floating IP and assign to droplet_name
    return await digitalOceanAPI("POST", `/v2/floating_ips`, {
      "droplet_id": dropletID
    });

  });
});

app.put('/floatingips/domainrecord_a/:name', async (req, res) => {
  exec(req, res, async () => {
    // Check if we can assign an IP address from the floating IP droplet
    const ret2 = await digitalOceanAPI("GET", "/v2/floating_ips");
    const fips = ret2.floating_ips;

    let ip = null;
    for (const doip of fips) {
      if (doip.droplet && doip.droplet.name === req.params.name) {
        ip = doip.ip;
      }
    }

    if (ip !== null) {
      const records = await digitalOceanAPI("GET", `/v2/domains/${req.params.name}/records`);
      const drecords = records.domain_records;

      for (const record of drecords) {
        // Update A type
        if (record.type === "A") {
          return await digitalOceanAPI("PUT", `/v2/domains/${req.params.name}/records/${record.id}`,
            {
              "name": "@",
              "data": ip,
            });
        }
      }
    }

    throw `Domain ${req.params.name}  doesn't have a floating IP address`;
  });
});

app.post('/createrepo/:owner/:name', async (req, res) => {
  try {
    const path = '/repos/ateventhorizon/portal/generate';

    const ret = await gitHubAPI("POST", path,
      {
        "owner": req.params.owner,
        "name": req.params.name,
        "description": "Bring it on!",
        "private": false
      });
    res.send(ret);
  } catch (e) {
    res.status(500);
    res.send(e);
  }

});

app.get('/', (req, res) => {
  res.send("Follow the white rabbit...");
});

const port = process.env.PORT || 3003;
app.listen(port, async () => {
  console.log('listening on *:' + port);
});
