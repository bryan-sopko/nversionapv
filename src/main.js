require('dotenv').config({ path: './.env' });
const tideliftAPI = require('./apiService/apiHandler.js');
const createCsvWriter = require('csv-writer').createObjectCsvWriter;
const path = require('path');

const CHUNK_SIZE = 1000;
const RATE_LIMIT_DELAY = 500; // 2 requests per second rate limit

async function main() {
    // Download the APV report
    const apv = await tideliftAPI.apvReport();
    let extractedData = [];
    let versionData = [];

    // Extract package platform and package name from the report
    apv.forEach(item => {
        let platform = item.violating_package_platform;
        let packageName = item.violating_package_name;
        // Save them to an array
        extractedData.push({
            platform: platform,
            name: packageName
        });
    });
    
    // Process the extracted data in chunks
    for (let i = 0; i < extractedData.length; i += CHUNK_SIZE) {
        const chunk = extractedData.slice(i, i + CHUNK_SIZE);
        console.log(`Processing chunk ${i/CHUNK_SIZE + 1} of ${Math.ceil(extractedData.length / CHUNK_SIZE)}`);
        await rateLimitedRequest(() => tideliftAPI.bulkPackageLookup(chunk)).then(versions => {
            versions.forEach(pkg => {
                let platform = pkg.platform;
                let name = pkg.name;
                let releases = pkg.releases; // object array of releases

                releases.sort((a, b) => new Date(b.published_at) - new Date(a.published_at));
                let lastThreeVersions = releases.slice(0, 3);
                // Add the extracted data to the array
                lastThreeVersions.forEach(release => {
                    versionData.push({
                        platform: platform,
                        name: name,
                        version: release.version,
                        latest_stable_release: pkg.latest_stable_release
                    });
                });
            });
        });
    }
    
    // Process version data in chunks
    let releaseVuln = [];
    for (let i = 0; i < versionData.length; i += CHUNK_SIZE) {
        const chunk = versionData.slice(i, i + CHUNK_SIZE);
        console.log(`Processing version data chunk ${i/CHUNK_SIZE + 1} of ${Math.ceil(versionData.length / CHUNK_SIZE)}`);
        await rateLimitedRequest(() => tideliftAPI.bulkReleaseLookup(chunk)).then(chunkReleaseVuln => {
            releaseVuln = releaseVuln.concat(chunkReleaseVuln);
        });
    }

    const values = await extractVulnerabilities(releaseVuln);
    const combinedApv = await combineReport(apv, values, versionData);
    await saveToCSV(combinedApv);
}

async function rateLimitedRequest(requestFn) {
    const result = await requestFn();
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_DELAY));
    return result;
}

async function combineReport(apv, nvalues, packageLookup) {
    nvalues.forEach(value => {
        apv.forEach(apvValue => {
            if (value.platform === apvValue.violating_package_platform && value.name === apvValue.violating_package_name) {
                packageLookup.forEach(package => {
                    if (package.platform === value.platform && value.name === package.name) {
                        const latestStableVersion = package.latest_stable_release?.version;

                        if (latestStableVersion) {
                            // Check if the client is on the N-1, N-2, and N-3 versions
                            const clientVersion = apvValue.violating_package_version;
                            const allVersions = value.versions.map(v => v.version);
                            const nMinus1Version = allVersions.length > 1 ? allVersions[1] : null;
                            const nMinus2Version = allVersions.length > 2 ? allVersions[2] : null;
                            const nMinus3Version = allVersions.length > 3 ? allVersions[3] : null;

                            apvValue["Client Version"] = clientVersion;
                            apvValue["Latest Stable Version"] = latestStableVersion;

                            // N-1
                            apvValue["Is N-1?"] = nMinus1Version ? (clientVersion === nMinus1Version ? "Yes" : "No") : null;
                            apvValue["N-1 Version"] = nMinus1Version;
                            apvValue["N-1 Same Major?"] = nMinus1Version ? (isSameMajorVersion(clientVersion, nMinus1Version) ? "Yes" : "No") : null;
                            apvValue["N-1 CVE"] = sanitizeField(getCVE(value.versions, nMinus1Version));
                            apvValue["N-1 Description"] = sanitizeField(getDescription(value.versions, nMinus1Version));
                            apvValue["N-1 Severity"] = sanitizeField(getSeverity(value.versions, nMinus1Version));

                            // N-2
                            apvValue["Is N-2?"] = nMinus2Version ? (clientVersion === nMinus2Version ? "Yes" : "No") : null;
                            apvValue["N-2 Version"] = nMinus2Version;
                            apvValue["N-2 Same Major?"] = nMinus2Version ? (isSameMajorVersion(clientVersion, nMinus2Version) ? "Yes" : "No") : null;
                            apvValue["N-2 CVE"] = sanitizeField(getCVE(value.versions, nMinus2Version));
                            apvValue["N-2 Description"] = sanitizeField(getDescription(value.versions, nMinus2Version));
                            apvValue["N-2 Severity"] = sanitizeField(getSeverity(value.versions, nMinus2Version));

                            // N-3
                            apvValue["Is N-3?"] = nMinus3Version ? (clientVersion === nMinus3Version ? "Yes" : "No") : null;
                            apvValue["N-3 Version"] = nMinus3Version;
                            apvValue["N-3 Same Major?"] = nMinus3Version ? (isSameMajorVersion(clientVersion, nMinus3Version) ? "Yes" : "No") : null;
                            apvValue["N-3 CVE"] = sanitizeField(getCVE(value.versions, nMinus3Version));
                            apvValue["N-3 Description"] = sanitizeField(getDescription(value.versions, nMinus3Version));
                            apvValue["N-3 Severity"] = sanitizeField(getSeverity(value.versions, nMinus3Version));
                        }
                    }
                });
                // Append nvalues to the APV report for that package
                apvValue.nvalues = value.versions;
            }
        });
    });
    return apv;
}

function isSameMajorVersion(version1, version2) {
    if (!version1 || !version2) return false;
    return version1.split('.')[0] === version2.split('.')[0];
}

function getCVE(versions, targetVersion) {
    if (!targetVersion) return null;
    const version = versions.find(v => v.version === targetVersion);
    return version ? version.cve : null;
}

function getDescription(versions, targetVersion) {
    if (!targetVersion) return null;
    const version = versions.find(v => v.version === targetVersion);
    return version ? version.description : null;
}

function getSeverity(versions, targetVersion) {
    if (!targetVersion) return null;
    const version = versions.find(v => v.version === targetVersion);
    return version ? version.severity : null;
}

function sanitizeField(field) {
    if (typeof field === 'string') {
        return field.replace(/[\r\n]+/g, ' ').trim();
    }
    return field;
}

async function extractVulnerabilities(vulns) {
    const vulnerabilities = {};
    console.log(vulns.length);
    vulns.forEach(pkg => {
        const platform = pkg.platform;
        const name = pkg.name;
        if (pkg.violations && pkg.violations.length > 0) {
            pkg.violations.forEach(violation => {
                if (violation.catalog_standard === 'vulnerabilities') {
                    const key = `${platform}:${name}`;
                    if (!vulnerabilities[key]) {
                        vulnerabilities[key] = {
                            platform: platform,
                            name: name,
                            versions: [],
                        };
                    }
                    vulnerabilities[key].versions.push({
                        version: pkg.version,
                        cve: violation.vulnerability.id,
                        description: violation.vulnerability.description,
                        severity: violation.vulnerability.severity
                    });
                }
            });
        } else {
            // Add entry with null values for cve, description, and severity if no violations
            const key = `${platform}:${name}`;
            if (!vulnerabilities[key]) {
                vulnerabilities[key] = {
                    platform: platform,
                    name: name,
                    versions: []
                };
            }
            vulnerabilities[key].versions.push({
                version: pkg.version,
                cve: null,
                description: null,
                severity: null
            });
        }
    });
    return Object.values(vulnerabilities);
}
function deduplicateArray(arr, key) {
    if (!Array.isArray(arr)) {
        // If arr is not an array, return an empty array to prevent errors
        return [];
    }

    const seen = new Set();
    return arr.filter(item => {
        const uniqueKey = key(item);
        if (seen.has(uniqueKey)) {
            return false;
        }
        seen.add(uniqueKey);
        return true;
    });
}

function deduplicateData(data) {
    return data.map(entry => {
        // Ensure nvalues exists and is an array before deduplicating
        if (Array.isArray(entry.nvalues)) {
            entry.nvalues = deduplicateArray(entry.nvalues, item => item.version);
        } else {
            entry.nvalues = []; // Default to an empty array if nvalues is not defined
        }

        return entry;
    });
}

async function saveToJSON(data) {
    const fs = require('fs');
    const jsonFilePath = path.join(__dirname, 'combined_report.json');

    // Deduplicate data before saving to JSON
    const deduplicatedData = deduplicateData(data);

    // Write the data to a JSON file
    fs.writeFileSync(jsonFilePath, JSON.stringify(deduplicatedData, null, 2));
    console.log('Combined report saved to combined_report.json');
}
async function saveToCSV(data) {
    const csvWriter = createCsvWriter({
        path: path.join(__dirname, 'combined_report.csv'),
        header: [
            // Include all original fields from APV report
            {id: 'project', title: 'Project'},
            {id: 'external_identifier', title: 'External Identifier'},
            {id: 'branch', title: 'Branch'},
            {id: 'catalog', title: 'Catalog'},
            {id: 'groups', title: 'Groups'},
            {id: 'violation_type', title: 'Violation Type'},
            {id: 'direct_package_name', title: 'Direct Package Name'},
            {id: 'direct_package_version', title: 'Direct Package Version'},
            {id: 'direct_package_version_published_at', title: 'Direct Package Version Published At'},
            {id: 'direct_package_is_unknown', title: 'Direct Package Is Unknown'},
            {id: 'direct_purl', title: 'Direct Purl'},
            {id: 'platform', title: 'Platform'},
            {id: 'violating_package', title: 'Violating Package'},
            {id: 'violating_version', title: 'Violating Version'},
            {id: 'violating_version_published_at', title: 'Violating Version Published At'},
            {id: 'violating_purl', title: 'Violating Purl'},
            {id: 'violation_first_introduced_at', title: 'Violation First Introduced At'},
            {id: 'dependency_chain', title: 'Dependency Chain'},
            {id: 'dependency_scope', title: 'Dependency Scope'},
            {id: 'dependency_type', title: 'Dependency Type'},
            {id: 'action', title: 'Action'},
            {id: 'action_status', title: 'Action Status'},
            {id: 'action_recommendation', title: 'Action Recommendation'},
            {id: 'recommended_dependency_chain', title: 'Recommended Dependency Chain'},
            {id: 'violation_title', title: 'Violation Title'},
            {id: 'violation_description', title: 'Violation Description'},
            {id: 'violation_allowed', title: 'Violation Allowed'},
            {id: 'violation_link', title: 'Violation Link'},
            {id: 'vulnerability_id', title: 'Vulnerability ID'},
            {id: 'severity', title: 'Severity'},
            {id: 'vulnerability_description', title: 'Vulnerability Description'},
            {id: 'vulnerability_date', title: 'Vulnerability Date'},
            {id: 'vulnerability_url', title: 'Vulnerability URL'},
            {id: 'severity_rating', title: 'Severity Rating'},
            {id: 'lifter_recommendations', title: 'Lifter Recommendations'},
            {id: 'report_date', title: 'Report Date'},
            // Add new fields
            {id: 'Client Version', title: 'Client Version'},
            {id: 'Latest Stable Version', title: 'Latest Stable Version'},
            {id: 'Is N-1?', title: 'Is N-1?'},
            {id: 'N-1 Version', title: 'N-1 Version'},
            {id: 'N-1 Same Major?', title: 'N-1 Same Major?'},
            {id: 'N-1 CVE', title: 'N-1 CVE'},
            {id: 'N-1 Description', title: 'N-1 Description'},
            {id: 'N-1 Severity', title: 'N-1 Severity'},
            {id: 'Is N-2?', title: 'Is N-2?'},
            {id: 'N-2 Version', title: 'N-2 Version'},
            {id: 'N-2 Same Major?', title: 'N-2 Same Major?'},
            {id: 'N-2 CVE', title: 'N-2 CVE'},
            {id: 'N-2 Description', title: 'N-2 Description'},
            {id: 'N-2 Severity', title: 'N-2 Severity'},
            {id: 'Is N-3?', title: 'Is N-3?'},
            {id: 'N-3 Version', title: 'N-3 Version'},
            {id: 'N-3 Same Major?', title: 'N-3 Same Major?'},
            {id: 'N-3 CVE', title: 'N-3 CVE'},
            {id: 'N-3 Description', title: 'N-3 Description'},
            {id: 'N-3 Severity', title: 'N-3 Severity'}
        ]
    });

    const records = data.map(item => ({
        project: sanitizeField(item.project),
        external_identifier: sanitizeField(item.external_identifier),
        branch: sanitizeField(item.branch),
        catalog: sanitizeField(item.catalog),
        groups: sanitizeField(item.groups),
        violation_type: sanitizeField(item.violation_type),
        direct_package_name: sanitizeField(item.direct_package_name),
        direct_package_version: sanitizeField(item.direct_package_version),
        direct_package_version_published_at: sanitizeField(item.direct_package_version_published_at),
        direct_package_is_unknown: sanitizeField(item.direct_package_is_unknown),
        direct_purl: sanitizeField(item.direct_purl),
        platform: sanitizeField(item.platform),
        violating_package: sanitizeField(item.violating_package),
        violating_version: sanitizeField(item.violating_version),
        violating_version_published_at: sanitizeField(item.violating_version_published_at),
        violating_purl: sanitizeField(item.violating_purl),
        violation_first_introduced_at: sanitizeField(item.violation_first_introduced_at),
        dependency_chain: sanitizeField(item.dependency_chain),
        dependency_scope: sanitizeField(item.dependency_scope),
        dependency_type: sanitizeField(item.dependency_type),
        action: sanitizeField(item.action),
        action_status: sanitizeField(item.action_status),
        action_recommendation: sanitizeField(item.action_recommendation),
        recommended_dependency_chain: sanitizeField(item.recommended_dependency_chain),
        violation_title: sanitizeField(item.violation_title),
        violation_description: sanitizeField(item.violation_description),
        violation_allowed: sanitizeField(item.violation_allowed),
        violation_link: sanitizeField(item.violation_link),
        vulnerability_id: sanitizeField(item.vulnerability_id),
        severity: sanitizeField(item.severity),
        vulnerability_description: sanitizeField(item.vulnerability_description),
        vulnerability_date: sanitizeField(item.vulnerability_date),
        vulnerability_url: sanitizeField(item.vulnerability_url),
        severity_rating: sanitizeField(item.severity_rating),
        lifter_recommendations: sanitizeField(item.lifter_recommendations),
        report_date: sanitizeField(item.report_date),
        'Client Version': sanitizeField(item['Client Version']),
        'Latest Stable Version': sanitizeField(item['Latest Stable Version']),
        'Is N-1?': sanitizeField(item['Is N-1?']),
        'N-1 Version': sanitizeField(item['N-1 Version']),
        'N-1 Same Major?': sanitizeField(item['N-1 Same Major?']),
        'N-1 CVE': sanitizeField(item['N-1 CVE']),
        'N-1 Description': sanitizeField(item['N-1 Description']),
        'N-1 Severity': sanitizeField(item['N-1 Severity']),
        'Is N-2?': sanitizeField(item['Is N-2?']),
        'N-2 Version': sanitizeField(item['N-2 Version']),
        'N-2 Same Major?': sanitizeField(item['N-2 Same Major?']),
        'N-2 CVE': sanitizeField(item['N-2 CVE']),
        'N-2 Description': sanitizeField(item['N-2 Description']),
        'N-2 Severity': sanitizeField(item['N-2 Severity']),
        'Is N-3?': sanitizeField(item['Is N-3?']),
        'N-3 Version': sanitizeField(item['N-3 Version']),
        'N-3 Same Major?': sanitizeField(item['N-3 Same Major?']),
        'N-3 CVE': sanitizeField(item['N-3 CVE']),
        'N-3 Description': sanitizeField(item['N-3 Description']),
        'N-3 Severity': sanitizeField(item['N-3 Severity'])
    }));

    await csvWriter.writeRecords(records);
    console.log('Combined report saved to combined_report.csv');
    await saveToJSON(data);
}

main();