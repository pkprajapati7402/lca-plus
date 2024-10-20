const express = require('express');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static files from the React app
app.use(express.static(path.join(__dirname, '../frontend/build')));

app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ message: "Invalid URL" });

  try {
    const response = await axios.get(url);
    const html = response.data;
    const $ = cheerio.load(html);
    const isSpammy = html.includes('win a prize') || html.includes('click here for free');
    let result = { safe: true, message: "Safe to Visit" };
    
    if (isSpammy) {
      result = { safe: false, danger: true, message: "This website may be spammy." };
    }
    
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: "Failed to analyze the website." });
  }
});

// Catch-all handler to send back the frontend app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/build/index.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
