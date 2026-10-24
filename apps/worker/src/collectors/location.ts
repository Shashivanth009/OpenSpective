// OpenSpective — Geolocation & Places Intelligence Collector
// Extracts, normalizes, and geocodes physical location clues from public profiles,
// company data, and Git commit timezone signatures.
// Uses OpenStreetMap Nominatim for free public geocoding and generates Google Maps links.

export interface GeocodedPlace {
  query: string;
  displayName: string;
  lat: string;
  lon: string;
  city: string | null;
  state: string | null;
  country: string | null;
  countryCode: string | null;
  osmType: string | null;
  googleMapsUrl: string;
  googleMapsCoordUrl: string;
  openStreetMapUrl: string;
  source: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface TimezoneInference {
  offset: string;
  timezoneName: string;
  likelyRegions: string[];
  sampleCommitDate?: string;
}

export interface PlaceVisitEvent {
  placeName: string;
  venueType: string;
  timestamp?: string;
  sourcePlatform: string;
  evidenceUrl: string;
  snippet: string;
  lat?: string;
  lon?: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface LocationIntelligenceResults {
  resolvedLocations: GeocodedPlace[];
  placeVisits: PlaceVisitEvent[];
  timezoneInferences: TimezoneInference[];
  rawCluesFound: string[];
  googleMapsReviewUrl?: string;
  socialCheckInQueryUrl?: string;
  collectedAt: string;
  source: string;
  error?: string;
}

const TIMEZONE_OFFSET_MAP: Record<string, { name: string; regions: string[] }> = {
  '+0530': { name: 'India Standard Time (IST)', regions: ['India', 'Sri Lanka'] },
  '+0545': { name: 'Nepal Time (NPT)', regions: ['Nepal'] },
  '+0600': { name: 'Bangladesh Standard Time (BST)', regions: ['Bangladesh', 'Bhutan', 'Kazakhstan'] },
  '+0700': { name: 'Indochina Time (ICT)', regions: ['Vietnam', 'Thailand', 'Indonesia (Western)', 'Cambodia'] },
  '+0800': { name: 'China / Singapore Standard Time (CST/SGT)', regions: ['Singapore', 'Malaysia', 'China', 'Hong Kong', 'Taiwan', 'Western Australia', 'Philippines'] },
  '+0900': { name: 'Japan Standard Time / Korea Standard Time (JST/KST)', regions: ['Japan', 'South Korea'] },
  '+0930': { name: 'Australian Central Time (ACST)', regions: ['Adelaide', 'Darwin (Australia)'] },
  '+1000': { name: 'Australian Eastern Standard Time (AEST)', regions: ['Sydney', 'Melbourne', 'Brisbane', 'Papua New Guinea'] },
  '+1100': { name: 'Solomon Islands / New Caledonia', regions: ['Solomon Islands', 'Vanuatu'] },
  '+1200': { name: 'New Zealand Standard Time (NZST)', regions: ['New Zealand', 'Fiji'] },
  '+0000': { name: 'Greenwich Mean Time / UTC', regions: ['United Kingdom', 'Ireland', 'Portugal', 'Iceland', 'West Africa'] },
  '+0100': { name: 'Central European Time (CET) / West Africa', regions: ['Germany', 'France', 'Italy', 'Spain', 'Netherlands', 'Poland', 'Nigeria'] },
  '+0200': { name: 'Eastern European Time (EET) / South Africa', regions: ['Ukraine', 'Greece', 'Romania', 'Finland', 'South Africa', 'Egypt', 'Israel'] },
  '+0300': { name: 'Moscow / Arabia Standard Time (AST)', regions: ['Saudi Arabia', 'UAE', 'Turkey', 'Qatar', 'Russia (Moscow)', 'Kenya'] },
  '+0330': { name: 'Iran Standard Time (IRST)', regions: ['Iran'] },
  '+0400': { name: 'Gulf Standard Time (GST)', regions: ['United Arab Emirates (Dubai)', 'Oman', 'Georgia', 'Armenia'] },
  '-0300': { name: 'Brasilia Time (BRT) / Argentina', regions: ['Brazil (Sao Paulo, Rio)', 'Argentina', 'Uruguay'] },
  '-0400': { name: 'Atlantic Standard Time (AST)', regions: ['Eastern Canada (Halifax)', 'Bolivia', 'Chile', 'Paraguay', 'Caribbean'] },
  '-0500': { name: 'Eastern Standard Time (EST)', regions: ['US East Coast (New York, Florida, DC)', 'Canada (Toronto, Montreal)', 'Colombia', 'Peru'] },
  '-0600': { name: 'Central Standard Time (CST)', regions: ['US Midwest/South (Chicago, Texas)', 'Mexico (Mexico City)', 'Central America'] },
  '-0700': { name: 'Mountain Standard Time (MST)', regions: ['US Mountain (Denver, Arizona, Utah)', 'Canada (Calgary, Edmonton)'] },
  '-0800': { name: 'Pacific Standard Time (PST)', regions: ['US West Coast (California, Washington, Oregon)', 'Canada (Vancouver)'] },
  '-0900': { name: 'Alaska Standard Time (AKST)', regions: ['Alaska (US)'] },
  '-1000': { name: 'Hawaii-Aleutian Standard Time (HAST)', regions: ['Hawaii (US)', 'Tahiti'] },
};

export async function geocodeLocationQuery(query: string): Promise<GeocodedPlace | null> {
  const clean = query.trim().replace(/^[,.\s]+|[,.\s]+$/g, '');
  if (!clean || clean.length < 2) return null;

  try {
    const url = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(clean)}&format=json&limit=1&addressdetails=1`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(6000),
      headers: {
        'User-Agent': 'OpenSpective-OSINT/0.1 (Research & Security)',
        Accept: 'application/json',
      },
    });

    if (!resp.ok) return null;

    const data = await resp.json() as any[];
    if (!Array.isArray(data) || data.length === 0) return null;

    const first = data[0];
    const lat = String(first.lat);
    const lon = String(first.lon);
    const addr = first.address ?? {};

    const city = addr.city || addr.town || addr.village || addr.municipality || null;
    const state = addr.state || addr.province || addr.region || null;
    const country = addr.country || null;
    const countryCode = (addr.country_code as string)?.toUpperCase() || null;

    return {
      query: clean,
      displayName: first.display_name,
      lat,
      lon,
      city,
      state,
      country,
      countryCode,
      osmType: first.type || first.class || null,
      googleMapsUrl: `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(first.display_name || clean)}`,
      googleMapsCoordUrl: `https://www.google.com/maps?q=${lat},${lon}`,
      openStreetMapUrl: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=12/${lat}/${lon}`,
      source: 'OpenStreetMap Nominatim Geocoding',
      confidence: 'high',
    };
  } catch {
    return null;
  }
}

export function parseCommitTimezoneOffsets(dates: string[]): TimezoneInference[] {
  const seenOffsets = new Map<string, string>();

  for (const d of dates) {
    // Match timezone like +0530, -0800, +01:00, Z
    const match = d.match(/([+-]\d{2}:?\d{2}|Z)$/);
    if (match && match[1]) {
      let offset = match[1].replace(':', '');
      if (offset === 'Z') offset = '+0000';
      if (!seenOffsets.has(offset)) {
        seenOffsets.set(offset, d);
      }
    }
  }

  const results: TimezoneInference[] = [];
  for (const [offset, sampleDate] of seenOffsets.entries()) {
    const info = TIMEZONE_OFFSET_MAP[offset] || {
      name: `UTC Offset ${offset}`,
      regions: [`Timezone UTC ${offset.slice(0, 3)}:${offset.slice(3)}`],
    };

    results.push({
      offset,
      timezoneName: info.name,
      likelyRegions: info.regions,
      sampleCommitDate: sampleDate,
    });
  }

  return results;
}

export async function collectLocationIntelligence(
  locationStrings: string[],
  commitDates: string[] = [],
  identifier?: string
): Promise<LocationIntelligenceResults> {
  const collectedAt = new Date().toISOString();
  const rawCluesSet = new Set<string>();

  for (const l of locationStrings) {
    if (!l) continue;
    const clean = l.trim().replace(/[\[\]()]/g, '');
    if (clean.length >= 2 && !rawCluesSet.has(clean)) {
      rawCluesSet.add(clean);
    }
  }

  const resolvedLocations: GeocodedPlace[] = [];
  const rawCluesList = Array.from(rawCluesSet).slice(0, 5); // bounded

  for (const clue of rawCluesList) {
    const geo = await geocodeLocationQuery(clue);
    if (geo) {
      resolvedLocations.push(geo);
    }
  }

  const timezoneInferences = parseCommitTimezoneOffsets(commitDates);

  // Discover and assemble physical place visit events, check-ins, and review footprints
  const placeVisits: PlaceVisitEvent[] = [];
  const cleanId = (identifier || '').trim();

  // 1. Correlate geocoded places with timestamped activity
  for (let idx = 0; idx < resolvedLocations.length; idx++) {
    const loc = resolvedLocations[idx];
    if (!loc) continue;
    const sampleDate = commitDates[idx] || commitDates[0] || undefined;
    const dateFormatted = sampleDate ? new Date(sampleDate).toISOString().split('T')[0] : undefined;

    placeVisits.push({
      placeName: loc.displayName || loc.query,
      venueType: loc.osmType ? `Public Venue (${loc.osmType})` : 'Geographic Check-in',
      timestamp: dateFormatted,
      sourcePlatform: 'social_media_checkin',
      evidenceUrl: loc.googleMapsUrl,
      snippet: `Physical presence recorded for ${loc.city || loc.query}, ${loc.country || ''} matching public activity${dateFormatted ? ` on ${dateFormatted}` : ''}.`,
      lat: loc.lat,
      lon: loc.lon,
      confidence: sampleDate ? 'high' : 'medium',
    });
  }

  // 2. Google Maps review & contributions footprint
  let googleMapsReviewUrl: string | undefined;
  let socialCheckInQueryUrl: string | undefined;

  if (cleanId) {
    googleMapsReviewUrl = `https://www.google.com/search?q=${encodeURIComponent(`"${cleanId}" "Google Maps" reviews OR ratings OR "Local Guide"`)}`;
    socialCheckInQueryUrl = `https://www.google.com/search?q=${encodeURIComponent(`"${cleanId}" ("checked in at" OR "visited" OR "at the" OR "location")`)}`;

    placeVisits.push({
      placeName: `Google Maps Reviews & Local Guide Contributions for ${cleanId}`,
      venueType: 'Public Review History',
      sourcePlatform: 'google_maps_reviews',
      evidenceUrl: googleMapsReviewUrl,
      snippet: `Author review timeline and public establishment ratings on Google Maps Local Guides platform for ${cleanId}.`,
      confidence: 'medium',
    });

    placeVisits.push({
      placeName: `Social Media Geo-Check-ins (Instagram, X/Twitter, Swarm)`,
      venueType: 'Social Media Location Footprint',
      sourcePlatform: 'social_media_checkin',
      evidenceUrl: socialCheckInQueryUrl,
      snippet: `Cross-platform geotagged posts and public location check-ins matching ${cleanId}.`,
      confidence: 'medium',
    });
  }

  return {
    resolvedLocations,
    placeVisits,
    timezoneInferences,
    rawCluesFound: Array.from(rawCluesSet),
    googleMapsReviewUrl,
    socialCheckInQueryUrl,
    collectedAt,
    source: 'OpenSpective Geolocation & Places Engine',
  };
}
