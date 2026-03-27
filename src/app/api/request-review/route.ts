import { NextRequest, NextResponse } from "next/server";
import * as nodemailer from "nodemailer";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { lead, scanSummary } = body;

    if (!lead?.email || !lead?.name) {
      return NextResponse.json({ error: "Missing lead info." }, { status: 400 });
    }

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

    // 1. Send internal notification to you
    await transporter.sendMail({
      from: `"CMMC Exposure Proof" <${fromAddress}>`,
      to: notifyEmail,
      subject: `🔥 Review Request: ${lead.name} — ${scanSummary.domain}`,
      html: `
        <div style="font-family: -apple-system, sans-serif; max-width: 600px;">
          <h2 style="color: #3b82f6;">New CMMC Review Request</h2>
          <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Name</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${lead.name}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email</td><td style="padding: 8px; border-bottom: 1px solid #eee;"><a href="mailto:${lead.email}">${lead.email}</a></td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Company</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${lead.company || "—"}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Title</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${lead.title || "—"}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Domain Scanned</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${scanSummary.domain}</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Findings</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${scanSummary.findingCount} findings</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Breaches</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${scanSummary.breachCount || 0} known</td></tr>
            <tr><td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email Security</td><td style="padding: 8px; border-bottom: 1px solid #eee;">${scanSummary.emailRating || "N/A"}</td></tr>
          </table>
          <h3>Executive Summary</h3>
          <p style="color: #555;">${scanSummary.executiveSummary}</p>
          <h3>Findings</h3>
          <ul style="color: #555;">
            ${scanSummary.findings?.map((f: string) => `<li>${f}</li>`).join("") || "<li>None</li>"}
          </ul>
          <h3>Red Flags</h3>
          <ul style="color: #555;">
            ${scanSummary.redFlags?.map((f: string) => `<li>${f}</li>`).join("") || "<li>None</li>"}
          </ul>
          <p style="color: #999; font-size: 12px; margin-top: 24px;">
            Sent from CMMC Exposure Proof — ${new Date().toISOString()}
          </p>
        </div>
      `,
    });

    // 2. Send confirmation to the prospect
    await transporter.sendMail({
      from: `"CinderLabs" <${fromAddress}>`,
      to: lead.email,
      subject: `Your CMMC Exposure Review — ${scanSummary.domain}`,
      html: `
        <div style="font-family: -apple-system, sans-serif; max-width: 600px; color: #333;">
          <div style="background: #0a0e17; padding: 24px; border-radius: 8px 8px 0 0;">
            <h1 style="color: #3b82f6; margin: 0; font-size: 20px;">CinderLabs</h1>
          </div>
          <div style="padding: 24px; border: 1px solid #eee; border-top: none; border-radius: 0 0 8px 8px;">
            <p>Hi ${lead.name.split(" ")[0]},</p>
            <p>Thank you for running a CMMC Exposure Proof scan on <strong>${scanSummary.domain}</strong>.</p>
            <p>We identified <strong>${scanSummary.findingCount} external findings</strong> that may be relevant to your CMMC readiness. A member of our team will review your results and reach out within <strong>24 business hours</strong> to discuss:</p>
            <ul>
              <li>Which findings represent real compliance risk vs. false positives</li>
              <li>Quick remediation opportunities</li>
              <li>How these findings map to your CMMC assessment scope</li>
            </ul>
            <p>In the meantime, you can revisit your report at <a href="https://exposure.cinderlabs.ai" style="color: #3b82f6;">exposure.cinderlabs.ai</a>.</p>
            <p style="margin-top: 24px;">Best,<br/><strong>The CinderLabs Team</strong></p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;" />
            <p style="color: #999; font-size: 12px;">
              CinderLabs — Cybersecurity & AI Risk Consultancy<br/>
              <a href="https://cinderlabs.ai" style="color: #3b82f6;">cinderlabs.ai</a>
            </p>
          </div>
        </div>
      `,
    });

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Review request email error:", err);
    return NextResponse.json(
      { error: "Failed to send review request. Please try again." },
      { status: 500 }
    );
  }
}
