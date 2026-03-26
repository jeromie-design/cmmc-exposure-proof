import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scanner";

export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const input = body.input?.trim();

    if (!input || input.length < 2 || input.length > 200) {
      return NextResponse.json(
        { error: "Please provide a valid company name or domain." },
        { status: 400 }
      );
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
