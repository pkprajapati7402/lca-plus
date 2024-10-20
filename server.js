const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');
const app = express();

// Use Google Safe Browsing API Key
const googleSafeBrowsingAPI = 'AIzaSyCoWIO1aDyV47g_lOyHKBTu0eBeTa3fSwQ';

app.use(express.json());
app.use(cors());  // Allow frontend requests from different domains

// Function to unshorten URLs using Unshorten.me
async function unshortenURL(url) {
  try {
    const unshortened = await axios.get(`https://unshorten.me/s/${encodeURIComponent(url)}`);
    return unshortened.data.resolved_url;
  } catch (error) {
    return url; // If any error, return the original URL
  }
}

app.post('/analyze', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ message: "Invalid URL" });

  try {
    // Step 1: Unshorten the URL if it's shortened
    url = await unshortenURL(url);

    // Step 2: Check Google Safe Browsing API for blacklisting
    const safeBrowsingResponse = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${googleSafeBrowsingAPI}`, {
      client: {
        clientId: "yourcompany",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [
          { url: url }
        ]
      }
    });

    // Check if the domain is flagged as unsafe by Google
    const safeBrowsingData = safeBrowsingResponse.data;
    if (safeBrowsingData && safeBrowsingData.matches) {
      return res.json({ safe: false, message: "This domain is blacklisted by Google Safe Browsing." });
    }

    // Step 3: Fetch the website's HTML content
    const response = await axios.get(url);
    const html = response.data;
    const $ = cheerio.load(html);

    // Step 4: Check for spammy content keywords
    const isSpammy = html.includes('win a prize') || html.includes('click here for free');
    if (isSpammy) {
      return res.json({ safe: false, message: "This website may be spammy." });
    }

    // Step 5: Check for suspicious structures (e.g., iframes, forms, scripts)
    const iframesCount = $('iframe').length;
    const formsCount = $('form').length;
    const externalScriptsCount = $('script[src]').length;

    if (iframesCount > 5 || formsCount > 3 || externalScriptsCount > 10) {
      return res.json({ safe: false, message: "This website contains suspicious elements like too many forms, iframes, or scripts." });
    }

    // If all checks pass, the website is safe
    res.json({ safe: true, message: "Safe to Visit" });

  } catch (error) {
    res.status(500).json({ message: "Failed to analyze the website." });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
