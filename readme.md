# Package Version and Vulnerability Checker

## Overview
This application checks the package versions for a given set of software packages and identifies if they are on the N-1, N-2, or N-3 versions. It also checks for any vulnerabilities associated with these versions. It then combines the results with the APV report and outputs the results in a CSV file.

## CSV Output
The CSV file will include all columns in the APV report along with new ones:

- `Project`
- `External Identifier`
- `Branch`
- `Catalog`
- `Groups`
- `Violation Type`
- `Direct Package Name`
- `Direct Package Version`
- `Direct Package Version Published At`
- `Direct Package Is Unknown`
- `Direct Purl`
- `Platform`
- `Violating Package`
- `Violating Version`
- `Violating Version Published At`
- `Violating Purl`
- `Violation First Introduced At`
- `Dependency Chain`
- `Dependency Scope`
- `Dependency Type`
- `Action`
- `Action Status`
- `Action Recommendation`
- `Recommended Dependency Chain`
- `Violation Title`
- `Violation Description`
- `Violation Allowed`
- `Violation Link`
- `Vulnerability ID`
- `Severity`
- `Vulnerability Description`
- `Vulnerability Date`
- `Vulnerability URL`
- `Severity Rating`
- `Lifter Recommendations`
- `Report Date`
- `Client Version`
- `Latest Stable Version`
- `Is N-1?`
- `N-1 Version`
- `N-1 Same Major?`
- `N-1 CVE`
- `N-1 Description`
- `N-1 Severity`
- `Is N-2?`
- `N-2 Version`
- `N-2 Same Major?`
- `N-2 CVE`
- `N-2 Description`
- `N-2 Severity`
- `Is N-3?`
- `N-3 Version`
- `N-3 Same Major?`
- `N-3 CVE`
- `N-3 Description`
- `N-3 Severity`

### Special Cases
- If only one version of a package is released, other version-related columns will be blank.
- If N-1, N-2, or N-3 versions do not have violations but have vulnerabilities, they will still appear in the output.
- If a specific N-x version does not have a vulnerability, the corresponding column will be left blank.


## How to Run
1. Ensure Node.js and npm are installed on your system.
2. Clone the repository to your local machine.
3. Navigate to the project directory.
4. Install dependencies:
   ```bash
   npm install axios csv-writer dotenv
   ```
5. Set up a `.env` file in the project root with the necessary API credentials:
    ```bash
    TIDELIFT_ORG_TOKEN=your_tidelift_api_token_here
    ORGANIZATION=your_tidelift_org
    CATALOG=your_tidelift_catalog
    BASE_URL=https://api.tidelift.com/external-api/v1/
    ```
6. Run the application:
   ```bash
   node src/main.js
   ```

This script processes packages and outputs the results to a CSV file called compinedreport.csv in the working directory.
