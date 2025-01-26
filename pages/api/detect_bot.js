import geoip from 'geoip-lite';
import { Whois } from 'whois-json';

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

const TRAFFIC_THRESHOLD = 10;
const TRAFFIC_TIMEFRAME = 30 * 1000;
const TRAFFIC_DATA = {};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

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
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) =>
      pattern.test(userAgent.toLowerCase())
    );

    let isp = 'Unknown';
    let isScraperISP = false;

    try {
      const whoisData = await Whois(ip);
      isp = [
        whoisData?.netname,
        whoisData?.organization,
        whoisData?.descr,
        whoisData?.remarks,
      ].filter(Boolean).join(' ') || 'Unknown';
      isScraperISP = SCRAPER_ISPS.some((knownISP) =>
        isp.toLowerCase().includes(knownISP.toLowerCase())
      );
    } catch (error) {
      console.error('Whois lookup failed:', error.message);
    }

    const now = Date.now();
    if (!TRAFFIC_DATA[ip]) {
      TRAFFIC_DATA[ip] = [];
    }
    TRAFFIC_DATA[ip] = TRAFFIC_DATA[ip].filter(
      (timestamp) => now - timestamp < TRAFFIC_TIMEFRAME
    );
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    const geoData = geoip.lookup(ip);
    if (isp === 'Unknown' && geoData?.org) {
      isp = geoData.org;
    }

    const country = geoData?.country || 'Unknown';

    console.log(`Detection Details for IP: ${ip}`);
    console.log(`Whois Data:`, isp);
    console.log(`User-Agent: ${userAgent}`);
    console.log(`Country: ${country}`);
    console.log(`Is Bot (User-Agent): ${isBotUserAgent}`);
    console.log(`Is Scraper ISP: ${isScraperISP}`);
    console.log(`Is Suspicious Traffic: ${isSuspiciousTraffic}`);

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
