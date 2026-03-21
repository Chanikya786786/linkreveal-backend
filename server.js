const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const axios = require('axios'); 

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors()); 
app.use(express.json()); 

// Health Check Route
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: "success", message: "LinkReveal backend engine is running perfectly." });
});

// ==========================================
// MODULE 2: URL Expansion Endpoint
// ==========================================
app.post('/api/expand', async (req, res) => {
    const { shortUrl } = req.body;

    if (!shortUrl) {
        return res.status(400).json({ error: "Please provide a shortUrl in the request body." });
    }

    try {
        const response = await axios.get(shortUrl, {
            maxRedirects: 0, 
            validateStatus: function (status) {
                return status >= 200 && status < 400; 
            }
        });

        if (response.status >= 300 && response.status < 400 && response.headers.location) {
            return res.status(200).json({
                originalUrl: shortUrl,
                expandedUrl: response.headers.location,
                status: "Expanded successfully"
            });
        } else {
            return res.status(200).json({
                originalUrl: shortUrl,
                expandedUrl: shortUrl,
                status: "No redirect found (already expanded)"
            });
        }

    } catch (error) {
        // 🔥 THE ARCHITECTURE UPGRADE 🔥
        // If the link is fake, dead, or blocked by your ISP's firewall, 
        // Axios will fail. Instead of throwing an error and stopping the app, 
        // we gracefully return the original URL so Google can still analyze it!
        console.log(`[WARNING] Expansion bypassed for ${shortUrl}`);
        return res.status(200).json({
            originalUrl: shortUrl,
            expandedUrl: shortUrl,
            status: "Unreachable - Bypassed directly to Analysis"
        });
    }
});

// ==========================================
// MODULE 3: Security Risk Assessment
// ==========================================
app.post('/api/analyze', async (req, res) => {
    const { targetUrl } = req.body;

    if (!targetUrl) {
        return res.status(400).json({ error: "Please provide a targetUrl to analyze." });
    }

    try {
        const apiKey = process.env.GOOGLE_API_KEY;
        const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

        // This is the specific payload structure Google requires
        const payload = {
            client: {
                clientId: "linkreveal-capstone",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: targetUrl }]
            }
        };

        const response = await axios.post(apiUrl, payload);

        // If Google finds a threat, it returns a "matches" array.
        // If it's safe, it returns an empty object {}.
        if (response.data && response.data.matches) {
            return res.status(200).json({
                url: targetUrl,
                status: "DANGER",
                threats: response.data.matches.map(match => match.threatType)
            });
        } else {
            return res.status(200).json({
                url: targetUrl,
                status: "SAFE",
                message: "No threats detected by Google Safe Browsing."
            });
        }

    } catch (error) {
        return res.status(500).json({ 
            error: "Failed to analyze URL", 
            details: error.message 
        });
    }
});

app.listen(PORT, () => {
    console.log(`[SERVER] LinkReveal engine firing on http://localhost:${PORT}`);
});