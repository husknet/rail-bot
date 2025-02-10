import axios from "axios";
import geoip from "geoip-lite";

// ✅ List of Allowed Origins
const ALLOWED_ORIGINS = [
  "https://azurerdr.z19.web.core.windows.net",
  "https://toon.net",
  "https://amy.com"
];

export default async function handler(req, res) {
  // ✅ Fix CORS Handling
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    res.setHeader("Access-Control-Allow-Origin", "null"); // Block unknown origins
  }
  
  res.setHeader("Access-Control-Allow-Methods", "OPTIONS, POST");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  // ✅ Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.status(200).end(); // Respond to preflight requests
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { user_agent: userAgent, ip } = req.body;
    if (!userAgent || !ip) {
      return res.status(400).json({ error: "Invalid request: Missing user_agent or IP." });
    }

    // ✅ Step 1: Detect bots via User-Agent patterns
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) =>
      pattern.test(userAgent.toLowerCase())
    );

    // ✅ Step 2: Detect bots via ISP using ipinfo.io
    let isp = "Unknown";
    let isScraperISP = false;
    try {
      const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}?token=ea0e4253eb865f`);
      if (ipInfoResponse.data) {
        isp = ipInfoResponse.data.company?.name || ipInfoResponse.data.asn?.name || "Unknown";
        isScraperISP = ["Google LLC", "Microsoft Corporation"].some((botISP) =>
          isp.toLowerCase().includes(botISP.toLowerCase())
        );
      }
    } catch (error) {
      console.error("IPInfo lookup failed:", error.message);
    }

    // ✅ Final bot detection result
    const isBot = isBotUserAgent || isScraperISP;
    
    // ✅ Send JSON response
    res.status(200).json({ is_bot: isBot, isp });

  } catch (error) {
    console.error("Error processing bot detection:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}
