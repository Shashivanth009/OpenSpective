// Worker environment bindings
export interface Env {
  // D1 database
  DB: D1Database;
  // R2 bucket for reports
  REPORTS: R2Bucket;
  // Workers AI
  AI: Ai;
  // Secrets
  JWT_SECRET: string;
  // Optional API keys
  VIRUSTOTAL_API_KEY?: string;
  SHODAN_API_KEY?: string;
  HAVE_I_BEEN_PWNED_API_KEY?: string;
  GITHUB_TOKEN?: string;
  IPINFO_TOKEN?: string;
  // Config
  ENVIRONMENT?: string;
  APP_VERSION?: string;
  FRONTEND_URL?: string;
}
