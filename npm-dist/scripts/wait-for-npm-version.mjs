const [packageName, version] = process.argv.slice(2);
if (!packageName || !version) throw new Error("usage: wait-for-npm-version.mjs <package> <version>");
const encoded = packageName.replace("/", "%2f");
for (let attempt = 1; attempt <= 6; attempt += 1) {
  const response = await fetch(`https://registry.npmjs.org/${encoded}/${version}`);
  if (response.ok) process.exit(0);
  if (attempt < 6) await new Promise((resolve) => setTimeout(resolve, 10000));
}
throw new Error(`exact NPM candidate version did not become readable: ${packageName}@${version}`);
