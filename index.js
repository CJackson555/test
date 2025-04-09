import express from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.get('/api/token', (req, res) => {
  const { client_id, account_id } = req.query;

  if (!client_id || !account_id || !process.env.PRIVATE_KEY) {
    return res.status(400).json({ error: 'Missing client_id, account_id, or PRIVATE_KEY' });
  }

  const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
  const now = Math.floor(Date.now() / 1000);

  const payload = {
    iss: client_id,
    scope: 'rest_webservices',
    aud: `https://${account_id}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token`,
    iat: now,
    exp: now + 300
  };

  try {
    const token = jwt.sign(payload, privateKey, { algorithm: 'ES256' });
    res.json({ jwt: token });
  } catch (err) {
    res.status(500).json({ error: 'JWT signing failed', details: err.message });
  }
});

app.listen(port, () => {
  console.log(`JWT server listening on port ${port}`);
});
