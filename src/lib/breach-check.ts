import { BreachInfo } from "./types";

// Uses the HIBP public API to check for breached domains
// This endpoint does NOT require an API key
export async function checkBreaches(domain: string): Promise<BreachInfo> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`,
      {
        signal: controller.signal,
        headers: {
          "User-Agent": "CMMCExposureProof/1.0",
          "Accept": "application/json",
        },
      }
    );
    clearTimeout(timeout);

    if (res.status === 404 || res.status === 204) {
      return {
        totalBreaches: 0,
        breaches: [],
        summary: `No known data breaches were found associated with ${domain} in public breach databases.`,
      };
    }

    if (!res.ok) {
      // Rate limited or other error — return gracefully
      return {
        totalBreaches: 0,
        breaches: [],
        summary: `Breach database check was inconclusive for ${domain}. Manual verification recommended.`,
      };
    }

    const data = await res.json();

    if (!Array.isArray(data) || data.length === 0) {
      return {
        totalBreaches: 0,
        breaches: [],
        summary: `No known data breaches were found associated with ${domain} in public breach databases.`,
      };
    }

    const breaches = data
      .map((b: Record<string, unknown>) => ({
        name: (b.Name as string) || "Unknown",
        date: (b.BreachDate as string) || "Unknown",
        dataClasses: (b.DataClasses as string[]) || [],
        pwnCount: (b.PwnCount as number) || 0,
      }))
      .sort((a: { pwnCount: number }, b: { pwnCount: number }) => b.pwnCount - a.pwnCount)
      .slice(0, 10); // Top 10

    const totalAccounts = breaches.reduce((sum: number, b: { pwnCount: number }) => sum + b.pwnCount, 0);
    const hasCredentials = breaches.some((b: { dataClasses: string[] }) =>
      b.dataClasses.some((dc: string) =>
        ["Passwords", "Email addresses", "Usernames"].includes(dc)
      )
    );

    let summary = `${domain} appears in ${data.length} known data breach${data.length > 1 ? "es" : ""}, affecting approximately ${totalAccounts.toLocaleString()} accounts.`;
    if (hasCredentials) {
      summary += ` Breaches include exposed credentials, which may create assessor scrutiny around credential management and incident response.`;
    }

    return {
      totalBreaches: data.length,
      breaches,
      summary,
    };
  } catch {
    return {
      totalBreaches: 0,
      breaches: [],
      summary: `Breach database check could not be completed for ${domain}. Manual verification recommended.`,
    };
  }
}
