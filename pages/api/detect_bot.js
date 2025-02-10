import axios from "axios";
import geoip from "geoip-lite";

// ✅ List of Allowed Origins (CORS Whitelist)
const ALLOWED_ORIGINS = new Set([
  "https://azurerdr.z19.web.core.windows.net",
  "https://toon.net",
  "https://amy.com"
]);

// ✅ Blacklisted ISPs (Known Bot Networks)
const SCRAPER_ISPS = new Set([
  "Google LLC",
  "Microsoft Corporation",
  "Amazon Technologies Inc.",
  "Cloudflare",
  "Oracle Corporation",
  "Hetzner Online GmbH",
  "OVH SAS",
  "Akamai Technologies",
  "Fastly",
  "Linode, LLC",
  "DigitalOcean",
  "Contabo GmbH",
  "Leaseweb",
  "Vultr",
  "Windscribe",
  "Censys, Inc.",
  "Zscaler, Inc."
]);

// ✅ Rate Limiting Settings (Suspicious Traffic Control)
const TRAFFIC_THRESHOLD = 10; // Max requests in a given timeframe
const TRAFFIC_TIMEFRAME = 30 * 1000; // 30 seconds
const TRAFFIC_DATA = new Map(); // Track requests by IP

export default async function handler(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    res.setHeader("Access-Control-Allow-Origin", "null"); // Block unknown origins
  }
  
  res.setHeader("Access-Control-Allow-Methods", "OPTIONS, POST");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  // ✅ Handle Preflight Requests (OPTIONS)
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  try {
    const { user_agent: userAgent, ip } = req.body;
    if (!userAgent || !ip) {
      res.status(400).json({ error: "Invalid request: Missing user_agent or IP." });
      return;
    }

    // ✅ Step 1: Detect Bots via User-Agent Patterns
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) => pattern.test(userAgent.toLowerCase()));

    // ✅ Step 2: Detect Suspicious ISPs
    let isp = "Unknown";
    let isScraperISP = false;
    try {
      const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}?token=ea0e4253eb865f`);
      if (ipInfoResponse.data) {
        isp = ipInfoResponse.data.company?.name || ipInfoResponse.data.asn?.name || "Unknown";
        isScraperISP = SCRAPER_ISPS.has(isp);
      }
    } catch (error) {
      console.error("IPInfo lookup failed:", error.message);
    }

    // ✅ Step 3: Track Suspicious Traffic Patterns (Rate Limiting)
    const now = Date.now();
    if (!TRAFFIC_DATA.has(ip)) {
      TRAFFIC_DATA.set(ip, []);
    }
    const requestTimestamps = TRAFFIC_DATA.get(ip);
    TRAFFIC_DATA.set(ip, requestTimestamps.filter((timestamp) => now - timestamp < TRAFFIC_TIMEFRAME));
    TRAFFIC_DATA.get(ip).push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA.get(ip).length > TRAFFIC_THRESHOLD;

    // ✅ Step 4: GeoIP Lookup (Backup Check)
    const geoData = geoip.lookup(ip);
    const country = geoData?.country || "Unknown";

    console.log(`Detection for IP: ${ip} | ISP: ${isp} | Country: ${country}`);
    console.log(`Bot (User-Agent): ${isBotUserAgent} | Bot ISP: ${isScraperISP} | Suspicious Traffic: ${isSuspiciousTraffic}`);

    // ✅ Final Decision: Block if Any Condition is Met
    const isBot = isBotUserAgent || isScraperISP || isSuspiciousTraffic;
    
    if (isBot) {
      console.log(`🚨 Blocking request from ${ip} (Bot detected)`);
      res.status(403).json({ error: "Access Denied: Suspicious activity detected." });
      return;
    }

    // ✅ Allow Legitimate Users
    res.status(200).json({
      is_bot: isBot,
      country,
      details: {
        bot_user_agent: isBotUserAgent,
        scraper_isp: isScraperISP,
        suspicious_traffic: isSuspiciousTraffic,
        isp
      }
    });

  } catch (error) {
    console.error("Error processing bot detection:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}
