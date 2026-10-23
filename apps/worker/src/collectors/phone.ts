// OpenSpective — International Phone Number Intelligence Collector
// E.164 numbering plan analysis, geographic attribution, line-type classification,
// and public OSINT search pivot generator. Free, passive, and privacy-compliant.

export interface PhoneIntelligenceResult {
  rawInput: string;
  e164Format: string;
  internationalFormat: string;
  nationalFormat: string;
  countryCode: string;
  countryName: string;
  isoCountry: string;
  region: string;
  lineType: 'mobile' | 'fixed_line' | 'toll_free' | 'voip' | 'satellite' | 'unknown';
  validLength: boolean;
  coordinates: { lat: number; lon: number } | null;
  osintPivots: Array<{ name: string; url: string; description: string }>;
  collectedAt: string;
  source: string;
  error?: string;
}

interface CountryDialingRule {
  name: string;
  iso: string;
  region: string;
  minLen: number;
  maxLen: number;
  lat: number;
  lon: number;
  mobilePrefixes?: string[];
  tollFreePrefixes?: string[];
}

const COUNTRY_DIALING_CODES: Record<string, CountryDialingRule> = {
  '1': { name: 'United States & Canada (NANP)', iso: 'US', region: 'North America', minLen: 10, maxLen: 10, lat: 38.8951, lon: -77.0364, tollFreePrefixes: ['800', '888', '877', '866', '855', '844', '833'] },
  '44': { name: 'United Kingdom', iso: 'GB', region: 'Europe', minLen: 10, maxLen: 10, lat: 51.5074, lon: -0.1278, mobilePrefixes: ['7'], tollFreePrefixes: ['800', '808'] },
  '91': { name: 'India', iso: 'IN', region: 'South Asia', minLen: 10, maxLen: 10, lat: 28.6139, lon: 77.2090, mobilePrefixes: ['6', '7', '8', '9'], tollFreePrefixes: ['1800'] },
  '49': { name: 'Germany', iso: 'DE', region: 'Europe', minLen: 10, maxLen: 11, lat: 52.5200, lon: 13.4050, mobilePrefixes: ['15', '16', '17'] },
  '33': { name: 'France', iso: 'FR', region: 'Europe', minLen: 9, maxLen: 9, lat: 48.8566, lon: 2.3522, mobilePrefixes: ['6', '7'] },
  '81': { name: 'Japan', iso: 'JP', region: 'East Asia', minLen: 10, maxLen: 10, lat: 35.6762, lon: 139.6503, mobilePrefixes: ['70', '80', '90'] },
  '86': { name: 'China', iso: 'CN', region: 'East Asia', minLen: 11, maxLen: 11, lat: 39.9042, lon: 116.4074, mobilePrefixes: ['13', '14', '15', '16', '17', '18', '19'] },
  '61': { name: 'Australia', iso: 'AU', region: 'Oceania', minLen: 9, maxLen: 9, lat: -35.2809, lon: 149.1300, mobilePrefixes: ['4'] },
  '55': { name: 'Brazil', iso: 'BR', region: 'South America', minLen: 10, maxLen: 11, lat: -15.7975, lon: -47.8919, mobilePrefixes: ['9'] },
  '7': { name: 'Russia & Kazakhstan', iso: 'RU', region: 'Eurasia', minLen: 10, maxLen: 10, lat: 55.7558, lon: 37.6173, mobilePrefixes: ['9'] },
  '39': { name: 'Italy', iso: 'IT', region: 'Europe', minLen: 9, maxLen: 10, lat: 41.9028, lon: 12.4964, mobilePrefixes: ['3'] },
  '34': { name: 'Spain', iso: 'ES', region: 'Europe', minLen: 9, maxLen: 9, lat: 40.4168, lon: -3.7038, mobilePrefixes: ['6', '7'] },
  '31': { name: 'Netherlands', iso: 'NL', region: 'Europe', minLen: 9, maxLen: 9, lat: 52.3676, lon: 4.9041, mobilePrefixes: ['6'] },
  '41': { name: 'Switzerland', iso: 'CH', region: 'Europe', minLen: 9, maxLen: 9, lat: 46.9480, lon: 7.4474, mobilePrefixes: ['7'] },
  '46': { name: 'Sweden', iso: 'SE', region: 'Europe', minLen: 9, maxLen: 9, lat: 59.3293, lon: 18.0686, mobilePrefixes: ['7'] },
  '65': { name: 'Singapore', iso: 'SG', region: 'Southeast Asia', minLen: 8, maxLen: 8, lat: 1.3521, lon: 103.8198, mobilePrefixes: ['8', '9'] },
  '971': { name: 'United Arab Emirates', iso: 'AE', region: 'Middle East', minLen: 9, maxLen: 9, lat: 24.4539, lon: 54.3773, mobilePrefixes: ['50', '52', '54', '55', '56', '58'] },
  '966': { name: 'Saudi Arabia', iso: 'SA', region: 'Middle East', minLen: 9, maxLen: 9, lat: 24.7136, lon: 46.6753, mobilePrefixes: ['5'] },
  '27': { name: 'South Africa', iso: 'ZA', region: 'Southern Africa', minLen: 9, maxLen: 9, lat: -25.7479, lon: 28.2293, mobilePrefixes: ['6', '7', '8'] },
  '234': { name: 'Nigeria', iso: 'NG', region: 'West Africa', minLen: 10, maxLen: 10, lat: 9.0765, lon: 7.3986, mobilePrefixes: ['7', '8', '9'] },
};

export async function collectPhoneIntelligence(phone: string): Promise<PhoneIntelligenceResult> {
  const collectedAt = new Date().toISOString();
  // Strip non-digit characters except leading +
  const digitsOnly = phone.replace(/[^\d+]/g, '');
  const normalizedDigits = digitsOnly.startsWith('+') ? digitsOnly.slice(1) : digitsOnly;

  // Match country code by longest prefix first
  const sortedPrefixes = Object.keys(COUNTRY_DIALING_CODES).sort((a, b) => b.length - a.length);
  let matchedPrefix = '';
  let rule: CountryDialingRule | null = null;

  for (const prefix of sortedPrefixes) {
    if (normalizedDigits.startsWith(prefix)) {
      matchedPrefix = prefix;
      rule = COUNTRY_DIALING_CODES[prefix]!;
      break;
    }
  }

  if (!rule) {
    return {
      rawInput: phone,
      e164Format: `+${normalizedDigits}`,
      internationalFormat: `+${normalizedDigits}`,
      nationalFormat: normalizedDigits,
      countryCode: 'Unknown',
      countryName: 'Unknown Country / International',
      isoCountry: 'XX',
      region: 'International',
      lineType: 'unknown',
      validLength: normalizedDigits.length >= 7 && normalizedDigits.length <= 15,
      coordinates: null,
      osintPivots: [
        { name: 'Google Search Dork', url: `https://www.google.com/search?q=%22%2B${normalizedDigits}%22`, description: 'Public web mentions of phone string' },
        { name: 'DuckDuckGo Search', url: `https://duckduckgo.com/?q=%22%2B${normalizedDigits}%22`, description: 'Privacy-first search indexing' },
      ],
      collectedAt,
      source: 'OpenSpective E.164 Engine',
    };
  }

  const subscriberNumber = normalizedDigits.slice(matchedPrefix.length);
  const validLength = subscriberNumber.length >= rule.minLen && subscriberNumber.length <= rule.maxLen;

  // Determine line type
  let lineType: PhoneIntelligenceResult['lineType'] = 'fixed_line';
  if (rule.tollFreePrefixes && rule.tollFreePrefixes.some(p => subscriberNumber.startsWith(p))) {
    lineType = 'toll_free';
  } else if (rule.mobilePrefixes && rule.mobilePrefixes.some(p => subscriberNumber.startsWith(p))) {
    lineType = 'mobile';
  }

  const e164 = `+${matchedPrefix}${subscriberNumber}`;
  const intlFormat = `+${matchedPrefix} ${subscriberNumber}`;

  // OSINT Search Dorks
  const osintPivots = [
    {
      name: 'Google Quote Search',
      url: `https://www.google.com/search?q=%22${encodeURIComponent(e164)}%22+OR+%22${encodeURIComponent(intlFormat)}%22`,
      description: 'Discover forums, social accounts, leaks, and listings indexed with this number',
    },
    {
      name: 'Sync.me Public Lookup',
      url: `https://sync.me/search/?number=${encodeURIComponent(e164)}`,
      description: 'Community-contributed caller identification footprint',
    },
    {
      name: 'Truecaller Web Directory',
      url: `https://www.truecaller.com/search/${rule.iso.toLowerCase()}/${encodeURIComponent(subscriberNumber)}`,
      description: 'Public listing directory check',
    },
    {
      name: 'WhatsApp Direct Contact Link',
      url: `https://wa.me/${encodeURIComponent(normalizedDigits)}`,
      description: 'Check active messaging status on WhatsApp (opens direct chat)',
    },
    {
      name: 'Telegram Username / Link Check',
      url: `https://t.me/+${encodeURIComponent(normalizedDigits)}`,
      description: 'Check public Telegram channel or contact link',
    },
  ];

  return {
    rawInput: phone,
    e164Format: e164,
    internationalFormat: intlFormat,
    nationalFormat: subscriberNumber,
    countryCode: `+${matchedPrefix}`,
    countryName: rule.name,
    isoCountry: rule.iso,
    region: rule.region,
    lineType,
    validLength,
    coordinates: { lat: rule.lat, lon: rule.lon },
    osintPivots,
    collectedAt,
    source: 'ITU-T E.164 International Telecommunication Engine',
  };
}
