const unique = [];
const path = require('path');
const fs = require('fs');

 
/**
 * URL to fetch the malware list from
 * ```json
 * [{"package_name":"@duckdb\/node-api","version":"1.3.3","reason":"MALWARE"}]
 * ```
 * @type {string}
 */
const malwareListURL = 'https://malware-list.aikido.dev/malware_predictions.json';
 
function readPackage(pkg, context) {
  const uniqueId = `${pkg.name}[${pkg.version}]`;
 
  if (!unique.includes(uniqueId)) {
    unique.push(uniqueId);
  }
 
  return pkg
}

function getMalwareList() {
  try {
    const filePath = path.resolve(__dirname, 'malware_predictions.json');
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading malware list:', err);
    return [];
  }
}
 
async function afterAllResolved(lockfile, context) {
  context.log(`Unique ${unique.length} packages processed ${JSON.stringify(unique, null, 2)}`);
  const malwareList = await getMalwareList();
  // Build sets for exact and wildcard matches
  const malwareExactSet = new Set();
  const malwareWildcardSet = new Set();
  malwareList.forEach(item => {
    if (item.version === '*') {
      malwareWildcardSet.add(item.package_name);
    } else {
      malwareExactSet.add(`${item.package_name}[${item.version}]`);
    }
  });
 
  const foundMalware = unique.filter(id => {
    if (malwareExactSet.has(id)) return true;
    // Check for wildcard match (ignore version)
    const pkgName = id.replace(/\[.*\]$/, '');
    return malwareWildcardSet.has(pkgName);
  });
 
  if (foundMalware.length > 0) {
    context.log('Malware detected in the following packages:');
    foundMalware.forEach(id => {
      // Try to find details for exact match first
      let details = malwareList.find(item => `${item.package_name}[${item.version}]` === id);
      if (!details) {
        // Fallback to wildcard match
        const pkgName = id.replace(/\[.*\]$/, '');
        details = malwareList.find(item => item.package_name === pkgName && item.version === '*');
      }
      context.log(`- ${id}: ${details ? details.reason : 'MALWARE'}`);
    });
    throw new Error('Malware detected in dependencies. Aborting installation.');
  } else {
    context.log('No malware detected in dependencies.');
  }
 
  return lockfile
}
 
module.exports = {
  hooks: {
    readPackage,
    afterAllResolved
  }
}
