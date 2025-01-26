import geoip from 'geoip-lite';
import { Whois } from 'whois-json';

// Known scraper ISPs
const SCRAPER_ISPS = [
  "Microsoft Corporation",
  "Netcraft",
  "DigitalOcean",
  "Amazon Technologies Inc.",
  "Google LLC",
  "Linode, LLC",
  "OVH SAS",
  "Hetzner Online GmbH",
  "Alibaba",
  "Oracle Corporation",
  "SoftLayer Technologies",
  "Fastly",
  "Cloudflare",
  "Akamai Technologies",
  "Hurricane Electric",
  "Hostwinds",
  "Choopa",
  "Contabo GmbH",
  "Leaseweb",
  "Scaleway",
  "Vultr",
  "Ubiquity",
];

// Traffic thresholds
const TRAFFIC_THRESHOLD = 10; // Max requests in timeframe
const TRAFFIC_TIMEFRAME = 30 * 1000; // 30 seconds
const TRAFFIC_DATA = {}; // Store request timestamps by IP

/**
 * Detects bots based on User-Agent, ISP, and traffic patterns.
 */
export default async function handler(req, res) {
  // Add CORS headers
  res.setHeader('Access-Control-Allow-Origin', 'https://outblook.chiletoons.cl'); // Update this to restrict to a specific domain if needed
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { user_agent: userAgent, ip } = req.body;

  if (!userAgent || !ip) {
    return res.status(400).json({ error: 'Invalid request: Missing user_agent or IP.' });
  }

  try {
    // 1. Detect bots via User-Agent patterns
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) =>
      pattern.test(userAgent.toLowerCase())
    );

    // 2. Detect bots via ISP (Whois lookup)
    let isScraperISP = false;
    let isp = 'Unknown';
    try {
      const whoisData = await Whois(ip);
      isp = whoisData?.netname || whoisData?.organization || 'Unknown';
      isScraperISP = SCRAPER_ISPS.some((knownISP) =>
        isp.toLowerCase().includes(knownISP.toLowerCase())
      );
    } catch (error) {
      console.error('Whois lookup failed:', error.message);
    }

    // 3. Check suspicious traffic patterns
    const now = Date.now();
    if (!TRAFFIC_DATA[ip]) {
      TRAFFIC_DATA[ip] = [];
    }
    TRAFFIC_DATA[ip] = TRAFFIC_DATA[ip].filter(
      (timestamp) => now - timestamp < TRAFFIC_TIMEFRAME
    );
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    // 4. Detect bot using GeoIP lookup (optional, to identify the country)
    const geoData = geoip.lookup(ip);
    const country = geoData?.country || 'Unknown';

    // Log the detection process
    console.log(`Detection Details for IP: ${ip}`);
    console.log(`User-Agent: ${userAgent}`);
    console.log(`ISP: ${isp}`);
    console.log(`Country: ${country}`);
    console.log(`Is Bot (User-Agent): ${isBotUserAgent}`);
    console.log(`Is Scraper ISP: ${isScraperISP}`);
    console.log(`Is Suspicious Traffic: ${isSuspiciousTraffic}`);

    // Final decision
    const isBot = isBotUserAgent || isScraperISP || isSuspiciousTraffic;

    res.status(200).json({
      is_bot: isBot,
      country,
      details: {
        bot_user_agent: isBotUserAgent,
        scraper_isp: isScraperISP,
        suspicious_traffic: isSuspiciousTraffic,
        isp,
      },
    });
  } catch (error) {
    console.error('Error processing bot detection:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}
