const [packageName, version, ...additionalPackages] = process.argv.slice(2);
if (!packageName || !version) {
  throw new Error("usage: wait-for-npm-version.mjs <package> <version> [additional-package ...]");
}

const packages = [packageName, ...additionalPackages];
let consecutiveCompleteChecks = 0;
for (let attempt = 1; attempt <= 12; attempt += 1) {
  const results = await Promise.all(packages.map(async (name) => {
    const encoded = name.replace("/", "%2f");
    const url = `https://registry.npmjs.org/${encoded}/${version}?acceptance=${Date.now()}-${attempt}`;
    const response = await fetch(url, {
      cache: "no-store",
      headers: { "cache-control": "no-cache" },
    });
    if (!response.ok) return { name, ready: false };
    const metadata = await response.json();
    return { name, ready: metadata.version === version };
  }));
  const pending = results.filter((result) => !result.ready).map((result) => result.name);
  if (pending.length === 0) {
    consecutiveCompleteChecks += 1;
    if (consecutiveCompleteChecks === 2) process.exit(0);
  } else {
    consecutiveCompleteChecks = 0;
    process.stdout.write(`Registry propagation pending for: ${pending.join(", ")}\n`);
  }
  if (attempt < 12) await new Promise((resolve) => setTimeout(resolve, 10000));
}
throw new Error(`exact NPM candidate version did not become consistently readable: ${packages.join(", ")}@${version}`);
