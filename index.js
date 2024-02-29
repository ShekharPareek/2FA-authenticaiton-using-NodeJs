const express = require('express');
const speakeasy = require('speakeasy');
const uuid = require('uuid');
const { JsonDB } = require('node-json-db');
const { Config } = require('node-json-db/dist/lib/JsonDBConfig')

const app = express();
app.use(express.json());

const db = new JsonDB(new Config('myDatabase', true, false, '/'));

app.get('/api', (req, res) => res.json({ message: `Welcome to the 2FA` }));

// register user and create Temp secreat

app.post('/api/register', (req, res) => {
    const id = uuid.v4();

    try {
        const path = `/user/${id}`;
        const temp_secret = speakeasy.generateSecret();
        const base32 = temp_secret; 
        db.push(path, { id, secret:temp_secret}); 
        res.json({ id, secret:temp_secret.base32 });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error occurred generating the secret' });
    }
});

// verify the user

app.post('/api/verify', async (req, res) => {
    const { token, userId } = req.body;

    try {
        const path = `/user/${userId}`;
        const user = await db.getData(path);
        const {base32:secret} = user.secret;

        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token
        });

        if (verified) {
            res.json({ verified: true });
        } else {
            res.json({ verified: false });
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error in user' });
    }
});

// Validate the user

app.post('/api/validate', (req, res) => {
    const { token, userId } = req.body;

    try {
        const path = `/user/${userId}`;
        const user = db.getData(path);
        const {base32:secret} = user.temp_secret;

        const validate = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token,window:6
        });

        if (validate) {
            // Update the secret in the database with the same key
            db.push(path, { id: userId, secret: user.temp_secret });
            res.json({ validate: true });
        } else {
            res.json({ validate: false });
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Error in user' });
    }
});

const PORT = process.env.PORT || 5500;

app.listen(PORT, () => console.log(`Port running on: ${PORT}`));
