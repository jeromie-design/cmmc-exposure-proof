import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scanner";

export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const input = body.input?.trim();
    const lead = body.lead; // { name, email, company, title? }

    if (!input || input.length < 2 || input.length > 200) {
      return NextResponse.json(
        { error: "Please provide a valid company name or domain." },
        { status: 400 }
      );
    }

    // Log lead info (in production, send to CRM/webhook)
    if (lead?.email) {
      console.log("[LEAD]", JSON.stringify({
        ...lead,
        target: input,
        timestamp: new Date().toISOString(),
      }));

      // If a webhook URL is configured, send lead data there
      const webhookUrl = process.env.LEAD_WEBHOOK_URL;
      if (webhookUrl) {
        fetch(webhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...lead,
            target: input,
            timestamp: new Date().toISOString(),
            source: "cmmc-exposure-proof",
          }),
        }).catch(() => { /* non-blocking */ });
      }
    }

    const result = await runScan(input);
    return NextResponse.json(result);
  } catch (err) {
    console.error("Scan error:", err);
    return NextResponse.json(
      { error: "Scan failed. Please try again." },
      { status: 500 }
    );
  }
}
