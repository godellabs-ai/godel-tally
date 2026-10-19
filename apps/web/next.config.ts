import type { NextConfig } from "next";

const configuredDevOrigins = (process.env.TALLY_ALLOWED_DEV_ORIGINS ?? "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const nextConfig: NextConfig = {
  output: process.env.TALLY_STATIC_EXPORT === "1" ? "export" : "standalone",
  images: { unoptimized: true },
  reactStrictMode: true,
  poweredByHeader: false,
  allowedDevOrigins: ["127.0.0.1", ...configuredDevOrigins],
  // make dev runs Next.js from apps/web; the repository's .local directory
  // must stay outside the Turbopack file watch root.
  turbopack: { root: process.cwd() },
};

export default nextConfig;
