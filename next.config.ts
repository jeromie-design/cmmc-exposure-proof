import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: [],
  turbopack: {
    root: ".",
  },
};

export default nextConfig;
