# This dictionary defines the configuration for each type of report the script can generate.
REPORTS = {
    "images": {
        "workload": "images",  # API endpoint path for this workload
        "scan_columns": ['Id', 'Region', 'Provider','accountId','ScanTime', 'PackageManager', 'ResourceID', 'ImageID', 'NVD CVSS3 Vector'],  # Columns to expect from the secondary get_scan_info() call
        "index_column": "Id",  # Column used to merge the two data sources
        "selected_columns": [  # A list of all columns to be included in the initial DataFrame for this report
            'accountId', 'Severity', 'Description', 'CVE ID', 'Exploit Available', 'Discovered', 'Age Days', 'Region', 'Provider',
            'ScanTime','ResourceID', 'ImageID','Id', 'Registry', 'Repository', 'Tag',  'Clusters', 'Hosts',  'CVSS',
            'Namespaces', 'Distro', 'Type',  'Digest','Packages', 'Source Package', 'Package Version', 'Package License','Package Path',
            'originPackageName','PURL','Fix Status', 'Fix Date', 'Vulnerability Link', 'Containers', 'Published', 'NVD CVSS3 Vector',
            'Package Manager',
        ],
        "column_for_aggregation": "Repository",
        "resource_type_column": "",  # Hardcoded value for the 'Resource Type' column in the final report
    },
    "serverless": {
        "workload": "serverless",
        "scan_columns": ['Id', 'Resource ID', 'region', 'accountId', 'ScanTime', 'date_discovered', 'Resource Tags', 'Lambda Layers', 'Lambda Package Type', 'File Path', 'Last Updated', 'Lambda Last Updated At', 'NVD CVSS3 Vector'],
        "index_column": "Id",
        "selected_columns": [
            'accountId', 'Severity', 'Description', 'CVE ID', 'Exploit Available', 'date_discovered', 'Age Days', 'Region', 'Provider',
            'ScanTime','Name', 'Id', 'Defended', 'Runtime', 'Type', 'Package Name', 'PURL', 'Package Version',
            'Package License', 'CVSS', 'Fix Status', 'Vulnerability Link', 'Risk Factors', 'Resource Tags', "Resource ID",
            "Container Image Tags", "Platform", "Image In Use Count", "File Path", 'Ami', 'Lambda Layers', 'Lambda Package Type',
            'Last Updated', 'Lambda Last Updated At', 'NVD CVSS3 Vector', 'Package Manager',
        ],
        "column_for_aggregation": "Runtime",
        "resource_type_column": "AWS_LAMBDA_FUNCTION",
    },
    "containers": {
        "workload": "containers",
        "scan_columns": ['Id', 'Region', 'Provider','accountId','ScanTime', 'PackageManager', 'ResourceID', 'NVD CVSS3 Vector'],
        "index_column": "Id",
        "selected_columns": [
            'accountId', 'Severity', 'Description', 'CVE ID', 'Exploit Available', 'Discovered', 'Age Days', 'Region', 'Provider',
            'ScanTime','ResourceID', 'Id', 'Registry', 'Repository', 'Tag',  'Clusters', 'Hosts',  'CVSS',
            'Namespaces', 'Distro', 'Type',  'Digest','Packages', 'Source Package', 'Package Version', 'Package License','Package Path',
            'originPackageName','PURL','Fix Status', 'Fix Date', 'Vulnerability Link', 'Containers', 'Published', 'NVD CVSS3 Vector',
            'Package Manager',
        ],
        "column_for_aggregation": "",
        "resource_type_column": "",
    },
    "registry": {
        "workload": "registry",
        "scan_columns": ['Id', 'Resource ID', 'region', 'accountId', 'Provider', 'ScanTime', 'date_discovered', 'NVD CVSS3 Vector'],
        "index_column": "Id",
        "selected_columns": [
            'accountId', 'Severity', 'Registry', 'CVE ID', 'Repository', 'Exploit Available', 'date_discovered', 'Age Days','region', 'ScanTime', 'Provider',
            'Description','Tag', 'Id', 'Distro', 'Compliance ID', 'Resource Tags', 'Result', 'Type', 'Packages', 'Source Package', 'Package Version',
            'Package License', 'CVSS', 'Fix Status','Published', 'Vulnerability Link', 'Package Path', 'PURL', 'Risk Factors',
            "Image In Use Count", "Resource ID", 'Ami', 'Lambda Layers', 'Lambda Package Type', 'File Path',
            'Lambda Last Updated At', 'NVD CVSS3 Vector', 'Package Manager',
        ],
        "resource_type_column": "AWS_ECR_CONTAINER_IMAGE",
    },
    "hosts": {
        "workload": "hosts",
        "scan_columns": ['Id', 'Hostname', 'Last Seen', 'Resource Tags', 'Ami', 'NVD CVSS3 Vector'],
        "index_column": "Hostname",
        "selected_columns": [
            'Account ID', 'Severity', 'Description', 'CVE ID', 'Exploit Available', 'Discovered', 'Age Days', 'Region', 'Provider','HostIP',
            'ScanTime', 'Resource Ipv4', 'Distro', 'Compliance ID','Result', 'Type', 'Packages', 'Source Package', 'Package Version',
            'Package License','Package Path','CVSS', 'Fix Status',  'Published', 'Cluster', 'Vulnerability Link',
            'Agentless','Resource ID', 'PURL', 'Risk Factors', 'Resource Tags', 'Container Image Tags', 'Last Seen', 'Ami',
            'Lambda Layers', 'Lambda Package Type', 'File Path', 'Lambda Last Updated At', 'NVD CVSS3 Vector', 'Package Manager',
        ],
        "column_for_aggregation": "Distro",
        "resource_type_column": "AWS_EC2_INSTANCE",
    }
}

# A class to hold string constants for report keys, preventing typos.
class ReportsSecureMapping:
    IMAGES = "images"
    REGISTRY = "registry"
    SERVERLESS = "serverless"
    CONTAINERS = "containers"
    HOSTS = "hosts"

# A dictionary to map API field names to more user-friendly column headers for the final Excel report.
COLUMNS_RENAMES = {
    "accountId": "AWS Account Id",
    "Account ID": "AWS Account Id",
    "ResourceID": "Resource ID",
    "ImageID": "Resource ID",
    "Image ID": "Resource ID",
    "Hostname": "Resource ID",
    "region": "Region",
    "CVE ID": "Vulnerability ID",
    "Discovered": "First Seen",
    "date_discovered": "First Seen",
    "ScanTime": "Last Seen",
    "Tag": "Container Image Tags",
    "Distro": "Platform",
    "Packages": "Affected Packages",
    "Package Name": "Affected Packages",
    "Package Version": "Package Installed Version",
    "Fix Status": "Fixed in Version",
    "CVSS": "NVD CVSS3 Score",
    "PURL": "Remediation",
    "Vulnerability Link": "Reference Urls",
    "Hosts": "Image In Use Count",
    "Runtime": "Platform",
}

# Defines the complete list and order of columns for the final, consolidated Excel report.
FINAL_REDEBAN_COLUMNS = [
    "AWS Account Id", "Account", "Severity", "Fix Available", "Finding Type",
    "Vulnerability ID", "Description", "Finding ARN", "First Seen", "Last Seen",
    "Last Updated", "Resource ID", "Container Image Tags", "Region", "Platform",
    "Resource Tags", "Affected Packages", "Package Installed Version", "Fixed in Version",
    "Package Remediation", "File Path", "Network Paths", "Age (Days)", "Remediation", "NVD CVSS3 Score",
    "NVD CVSS3 Vector", "Resource Type", "Ami", "Resource Public Ipv4", "Resource Private Ipv4",
    "Resource Ipv6", "Resource Vpc", "Port Range", "Exploit Available", "Last Exploited At", "Lambda Layers",
    "Lambda Package Type", "Lambda Last Updated At", "Reference Urls", "Detector Name", "Package Manager",
    "Image Last In Use At", "Image In Use Count"
]

# A list of columns that will be added to the final report but left intentionally blank.
BLANK_COLUMNS = [
    "Finding ARN", "Network Paths",
    "Resource Public Ipv4", "Resource Private Ipv4", "Resource Ipv6", "Resource Vpc",
    "Port Range",  "Detector Name", "Image Last In Use At",
    "Image In Use Count",
]

# A default value for when a package type cannot be determined.
GENERIC_PACKAGE = "GENERIC"
# The dictionary that maps Prisma Cloud's `packageType` to the desired "Package Manager" format for the report.
REAL_PACKAGE_NAMES = {
    "nodejs": "NODE",
    "gem": "RUBY",
    "python": "PYTHON",
    "jar": "JAVA",
    "java": "JAVA",           
    "package": "OS",
    "windows": "OS",
    "os": "OS",              
    "application": "OS",     
    "app": "OS",
    "binary": "BINARY",
    "nuget": "NUGET",
    "go": "GO",
    "unknown": GENERIC_PACKAGE,
}

OS_COMMAND_MAP = {
    # Key: Fully normalized platform name (lowercase, no spaces/hyphens/underscores)
    'amznal2': 'yum update',
    'amazonlinux2': 'yum update',
    'amznal2023': 'dnf update',
    'redhatrhel9': 'dnf update',
    'redhatrhel8': 'dnf update',
    'rhel9': 'dnf update',
    'rhel8': 'dnf update',
    'rhel7': 'yum update',
    'oracleoel8': 'dnf update',
    'oracleoel7': 'yum update',
    'centos7': 'yum update',
    'ubuntunoble': 'apt install --only-upgrade',
    'ubuntufocal': 'apt install --only-upgrade',
    'ubuntu': 'apt install --only-upgrade',
    'debianbuster': 'apt install --only-upgrade',
    'debianbookworm': 'apt install --only-upgrade',
    'debiantrixie': 'apt install --only-upgrade',
    'debianbullseye': 'apt install --only-upgrade',
    'debian': 'apt install --only-upgrade',
    'alpine': 'apk upgrade', # General 'alpine' for all versions
    'chainguard': 'apk upgrade',
    'windows': 'Patch using Windows Update',
}