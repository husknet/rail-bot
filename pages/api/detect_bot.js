import axios from 'axios';
import geoip from 'geoip-lite';

// Known scraper ISPs
const SCRAPER_ISPS = [
  "RGT/SMP",
  "tzulo, inc.",
  "Cyber Assets FZCO",
  "Falco Networks B.V.",
  "PJSC Rostelecom",
  "Gtd Internet S.A.",
  "Meta Networks Inc",
  "PRIVATE LAYER INC",
  "Bucklog SARL",
  "FBW Reseaux Fibres inc.",
  "OpenVPN",
  "Huawei Cloud Hongkong Region",
  "Excitel Broadband Pvt Ltd",
  "VPN Consumer Frankfurt, Germany",
  "M Nets SAL",
  "HostRoyale Technologies Pvt Ltd",
  "The Constant Company, LLC",
  "bgm",
  "Microcom Informatique, Inc.",
  "Contabo Inc",
  "TELECABLE RESIDENCIAL",
  "Network for Tor-Exit traffic.",
  "LogicWeb Inc.",
  "Microsoft Corp",
  "Google LLC",
  "Microsoft Corporation",
  "Contabo Inc.",
  "Unknown",
  "Barry Hamel Equipment Ltd",
  "Charter Communications",
  "DLF Cable Network",
  "Packethub S.A.",
  "DataCamp s.r.o.",
  "Bharti Airtel Limited",
  "Clouvider",
  "Facebook",
  "Internet Archive",
  "QuickPacket, LLC",
  "Amazon Data Services Singapore",
  "PJSC MTS Sverdlovsk region",
  "HOME_DSL",
  "Amazon Data Services NoVa",
  "M247 LTD Berlin Infrastructure",
  "BRETAGNE TELECOM SASU",
  "M247 Ltd - Brazil Infrastructure",
  "ZAP-Hosting.com - IF YOU WANT MORE POWER",
  "ZAP-Hosting GmbH",
  "Artic Solutions SARL",
  "UCLOUD",
  "Cox Communications Inc.",
  "ONYPHE SAS",
  "Internet Utilities Europe and Asia Limited",
  "KYOCERA AVX Components (Dresden) GmbH",
  "Blix Group AS",
  "Kaopu Cloud HK Limited",
  "Cyber Assets FZCO",
  "Total server solutions LLC",
  "Internet Utilities Africa (PTY) LTD",
  "Atria Convergence Technologies Ltd.,",
  "Linode",
  "Bayer AG, Germany, Leverkusen",
  "TeraGo Networks Inc.",
  "Microsoft Corporation",
  "Zscaler, Inc.",
  "BT global Communications India Private Limited-Access",
  "Not SURF Net",
  "Nothing to hide",
  "TOTAL PLAY TELECOMUNICACIONES SA DE CV",
  "Driftnet Ltd",
  "Telstra Limited",
  "OVH US LLC",
  "TT DOTCOM SDN BHD",
  "OVH (NWK)",
  "Zayo Bandwidth",
  "Accenture LLP",
  "Kyivstar GSM",
  "Cascades",
  "Microsoft Limited",
  "Netcraft",
  "Rockion LLC",
  "Sudhana Telecommunications Private Limited",
  "COMPASS COMPRESSION SERVICES LTD",
  "DigitalOcean",
  "Amazon Technologies Inc.",
  "Google LLC",
  "Datacamp Limited",
  "Helsinki, Finland",
  "NorthernTel Limited Partnership",
  "China Unicom Shandong province network",
  "CHINA UNICOM Shanghai city network",
  "China Unicom Henan province network",
  "KDDI CORPORATION",
  "Reliance Jio Infocomm Limited",
  "Linode, LLC",
  "OVH SAS",
  "OVH Hosting, Inc.",
  "Hetzner Online GmbH",
  "Alibaba",
  "Oracle Corporation",
  "SoftLayer Technologies",
  "Fastly",
  "Cloudflare",
  "Cloudflare London, LLC",
  "Akamai Technologies",
  "Akamai Technologies Inc.",
  "Hurricane Electric",
  "Hostwinds",
  "Choopa",
  "Contabo GmbH",
  "Leaseweb",
  "Censys, Inc.",
  "Windscribe",
  "Hatching International B.V.",
  "Asm Technologies",
  "Leaseweb Deutschland GmbH",
  "Amazon.com, Inc.",
  "Amazon Data Services Ireland Limited",
  "Scaleway",
  "Vultr",
  "Ubiquity",
];

const TRAFFIC_THRESHOLD = 10; // Max requests in the given timeframe
const TRAFFIC_TIMEFRAME = 30 * 1000; // 30 seconds
const TRAFFIC_DATA = {}; // Store request timestamps by IP

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
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
    // Step 1: Detect bots via User-Agent patterns
    const botPatterns = [/bot/, /scraper/, /crawl/, /spider/, /httpclient/, /python/];
    const isBotUserAgent = botPatterns.some((pattern) =>
      pattern.test(userAgent.toLowerCase())
    );

    // Step 2: Detect bots via ISP using ipinfo.io
    let isp = 'Unknown';
    let isScraperISP = false;
    try {
      const ipInfoResponse = await axios.get(`https://ipinfo.io/${ip}?token=21399687d4c800`);
      if (ipInfoResponse.data) {
        isp = ipInfoResponse.data.company?.name || ipInfoResponse.data.asn?.name || 'Unknown';
        isScraperISP = SCRAPER_ISPS.some((knownISP) =>
          isp.toLowerCase().includes(knownISP.toLowerCase())
        );
      } else {
        console.error(`IPInfo lookup failed for IP: ${ip}`);
      }
    } catch (error) {
      console.error('IPInfo lookup failed:', error.message);
    }

    // Step 3: Check suspicious traffic patterns
    const now = Date.now();
    if (!TRAFFIC_DATA[ip]) {
      TRAFFIC_DATA[ip] = [];
    }
    TRAFFIC_DATA[ip] = TRAFFIC_DATA[ip].filter(
      (timestamp) => now - timestamp < TRAFFIC_TIMEFRAME
    );
    TRAFFIC_DATA[ip].push(now);
    const isSuspiciousTraffic = TRAFFIC_DATA[ip].length > TRAFFIC_THRESHOLD;

    // Step 4: GeoIP lookup as a backup
    const geoData = geoip.lookup(ip);
    const country = geoData?.country || 'Unknown';

    console.log(`Detection Details for IP: ${ip}`);
    console.log(`ISP: ${isp}`);
    console.log(`User-Agent: ${userAgent}`);
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
