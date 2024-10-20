const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');
const { URL } = require('url');
const https = require('https');

const app = express();

app.use(express.json());
app.use(cors());

const spammyKeywords = [
  'win a prize', 
  'click here for free', 
  'you have won', 
  'free download', 
  'limited offer', 
  'get rich quick',
  'act now',
  'earn money fast',
  'congratulations',
  'claim your prize'
];

// Function to check for SSL certificate validity
const checkSSL = (url) => {
  return new Promise((resolve) => {
    const parsedUrl = new URL(url);
    const options = {
      host: parsedUrl.hostname,
      port: 443,
      method: 'GET',
    };

    const req = https.request(options, (res) => {
      const valid = res.socket.authorized;
      resolve(valid);
    });

    req.on('error', () => {
      resolve(false);
    });

    req.end();
  });
};

app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ message: "Invalid URL" });

  try {
    const response = await axios.get(url);
    const html = response.data;
    const $ = cheerio.load(html);

    // Check for spammy keywords
    const isSpammy = spammyKeywords.some(keyword => html.toLowerCase().includes(keyword.toLowerCase()));

    // Check for metadata analysis
    const metaDescription = $('meta[name="description"]').attr('content') || '';
    const metaKeywords = $('meta[name="keywords"]').attr('content') || '';
    const metaSpammy = spammyKeywords.some(keyword => 
      metaDescription.toLowerCase().includes(keyword.toLowerCase()) ||
      metaKeywords.toLowerCase().includes(keyword.toLowerCase())
    );

    // Check if the SSL certificate is valid
    const sslValid = await checkSSL(url);

    let result = { safe: true, message: "Safe to Visit", sslValid };

    if (isSpammy || metaSpammy) {
      result = { 
        safe: false, 
        danger: true, 
        message: "This website may be spammy or unsafe.", 
        sslValid 
      };
    } else if (!sslValid) {
      result = { 
        safe: false, 
        danger: true, 
        message: "This website has an invalid SSL certificate.", 
        sslValid 
      };
    }

    res.json(result);

  } catch (error) {
    res.status(500).json({ message: "Failed to analyze the website." });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
