import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Critical Bug Bounty Workflow",
  description:
    "Authorized safe-harbor workflow for finding and validating critical software vulnerabilities."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
