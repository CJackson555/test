import express from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.get('/api/token', (req, res) => {
  // --- ADD userId to the destructured query parameters ---
  const { client_id, account_id, userId } = req.query;

  // --- UPDATE validation to include userId ---
  if (!client_id || !account_id || !userId || !process.env.PRIVATE_KEY) {
    // --- UPDATE error message ---
    return res.status(400).json({ error: 'Missing client_id, account_id, userId, or PRIVATE_KEY' });
  }

  const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: client_id,          // Issuer (Consumer Key / Client ID)
    scope: 'rest_webservices', // Scope(s) requested
    aud: `https://${account_id}.suitetalk.api.netsuite.com/services/rest/oauth2/v1/token`, // Audience (NetSuite Token Endpoint)
    iat: now,                // Issued At timestamp
    exp: now + 300,          // Expiration timestamp (e.g., 5 minutes from now)
    // --- ADD the sub (Subject) claim using the userId query parameter ---
    sub: userId              // Subject (NetSuite Internal ID of the user)
  };

  try {
    // Ensure the algorithm matches your private key type (ES256 for Elliptic Curve)
    const token = jwt.sign(payload, privateKey, { algorithm: 'ES256' });
    res.json({ jwt: token });
  } catch (err) {
    res.status(500).json({ error: 'JWT signing failed', details: err.message });
  }
});

app.listen(port, () => {
  console.log(`JWT server listening on port ${port}`);
});
