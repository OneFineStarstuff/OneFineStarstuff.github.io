export const metadata = { title: 'AGI/ASI Interface', description: 'AI Readiness MVP' };
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50 text-slate-900 antialiased">
        <div className="mx-auto max-w-5xl p-4">{children}</div>
      </body>
    </html>
  );
}
