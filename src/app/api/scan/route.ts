import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scanner";
import * as nodemailer from "nodemailer";

export const maxDuration = 60;

// Send lead notification email (non-blocking)
async function sendLeadNotification(lead: { name: string; email: string; company?: string; title?: string }, target: string) {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.zoho.com",
      port: parseInt(process.env.SMTP_PORT || "465"),
      secure: true,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const fromAddress = process.env.SMTP_FROM || process.env.SMTP_USER;
    const notifyEmail = process.env.NOTIFY_EMAIL || process.env.SMTP_USER;

    await transporter.sendMail({
      from: `"CMMC Exposure Proof" <${fromAddress}>`,
      to: notifyEmail,
      subject: `📋 New Lead: ${lead.name} scanned ${target}`,
      html: `
        <div style="font-family: -apple-system, sans-serif; max-width: 600px;">
          <h2 style="color: #e8631e;">New Exposure Proof Lead</h2>
          <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Name</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${lead.name}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email</td><td style="padding: 8px; border-bottom: 1px solid #eee;"><a href="mailto:${lead.email}">${lead.email}</a></td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Company</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${lead.company || "—"}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Title</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${lead.title || "—"}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Domain Scanned</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${target}</td></tr>
          </table>
          <p style="color: #999; font-size: 12px;">Sent from CMMC Exposure Proof — ${new Date().toISOString()}</p>
        </div>
      `,
    });
  } catch (err) {
    console.error("[LEAD EMAIL ERROR]", err);
  }
}

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

    // Log lead info and send notification email
    if (lead?.email) {
      console.log("[LEAD]", JSON.stringify({
        ...lead,
        target: input,
        timestamp: new Date().toISOString(),
      }));

      // Send email notification (non-blocking)
      sendLeadNotification(lead, input).catch(() => {});
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
