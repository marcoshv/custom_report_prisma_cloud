import datetime
import json

from io import BytesIO
from urllib.error import HTTPError
from urllib.request import urlopen

import re

import pandas as pd
import api
from io import StringIO

from api import NoProperResponseError
from helpers.helper import ReportsSecureMapping, REPORTS, FINAL_REDEBAN_COLUMNS, \
    COLUMNS_RENAMES, BLANK_COLUMNS, REAL_PACKAGE_NAMES, GENERIC_PACKAGE, OS_COMMAND_MAP

import logging
logging.basicConfig(format="%(levelname)s | %(asctime)s | %(filename)s:%(lineno)s | %(message)s", level=logging.INFO)
#logging.basicConfig(filename='script_output.log', filemode='w', format="%(levelname)s | %(asctime)s | %(filename)s:%(lineno)s | %(message)s", level=logging.INFO)

class CWPReportData:
    def __init__(self, report_key):
        # api
        self.token = api.get_token()
        self.console_token = api.get_console_token()

        # report
        self.report_key = report_key
        self.report = REPORTS.get(report_key)

        # extra info
        self.account_names = self.get_cloud_account_info()
        self.vms_data = None
        if self.report_key == ReportsSecureMapping.HOSTS:
            self.vms_data = self.get_vms_data()

    # api calls
    def download_vulnerability_report(self):
        # parameters
        params = {
            'normalizedSeverity': 'true',
            'issueType': 'vulnerabilities'
        }
        if self.report_key == ReportsSecureMapping.CONTAINERS:
            params.update({'agentless': 'true'})

        # download the vulnerability report from Prisma Cloud
        response = api.compose_console_get_request(
            self.console_token,
            url_complement=f"{self.report.get('workload')}/download",
            params=params,
        )
        return response

    def get_scan_info(self):
        # parameters to manipulate recovered data
        params = {
            'offset': 0,
            'limit': 100
        }
        if self.report_key in (ReportsSecureMapping.REGISTRY, ReportsSecureMapping.SERVERLESS, ReportsSecureMapping.HOSTS):
            params.update({'issueType': 'vulnerabilities'})
        elif self.report_key == ReportsSecureMapping.CONTAINERS:
            params.update({'agentless': True})

        report_data = {}
        while True:
            response = api.compose_console_get_request(
                self.console_token,
                url_complement=self.report.get('workload'),
                params=params
            )

            if not response or not hasattr(response, "content"):  # check if the response is empty
                break # no more data to fetch

            response_content = json.loads(response.content)

            for item in response_content:
                record_id = item.get("_id", "N/A")

                # inside the vulnerabilities key
                vulnerabilities = item.get("vulnerabilities") or []
                try:
                    package_names, vectors = zip(*{
                        (vulnerability.get("packageType"), vulnerability.get("vecStr")) for vulnerability in vulnerabilities
                    })
                except ValueError:
                    vectors, package_names = "", GENERIC_PACKAGE
                else:
                    vectors = next((record for record in vectors if record), None)
                    package_names = ",".join(set([REAL_PACKAGE_NAMES.get(record, GENERIC_PACKAGE) for record in package_names if record]))

                # inside the cloudmetadata key
                cloud_metadata = item.get("cloudMetadata", {})

                if self.report_key == ReportsSecureMapping.REGISTRY:
                    report_data[record_id] = {
                        'Resource ID': item['id'], # id = ImageId
                        'Region': cloud_metadata['region'],
                        'Account ID': cloud_metadata['accountID'],
                        'Provider': cloud_metadata['provider'],
                        'Last Seen': item['scanTime'],
                        'First Seen': item["firstScanTime"],
                        'NVD CVSS3 Vector': vectors,
                    }

                elif self.report_key == ReportsSecureMapping.IMAGES:
                    report_data[record_id] = {
                        'Region': cloud_metadata.get('region'),
                        'Provider': cloud_metadata.get('provider'),
                        'Account ID': cloud_metadata.get('accountID'),
                        'Last Seen': item.get('scanTime'),
                        'PackageManager': item.get('packageManager'),
                        'ResourceID': cloud_metadata.get('resourceID'),
                        'ImageID': cloud_metadata.get('image'),
                        'NVD CVSS3 Vector': vectors,
                    }

                elif self.report_key == ReportsSecureMapping.SERVERLESS:
                    report_data[record_id] = {
                        'Resource ID': record_id,
                        'Region': cloud_metadata['region'],
                        'Account ID': cloud_metadata['accountID'],
                        'Last Seen': item['scanTime'],
                        'First Seen': item['vulnerabilities'][0]['discovered'] if item.get(
                            'vulnerabilities') else None,
                        'Resource Tags': ",".join(
                            [f"{tag['key']}:{tag['value']}" for tag in item.get('functionTags', [])]),
                        'Lambda Layers': ",".join({f"{layer['id']}" for layer in item.get('functionLayers', [])}),
                        'Lambda Package Type': "",
                        'File Path': item.get('packages'),
                        'Last Updated': item.get('lastModified'),
                        'Lambda Last Updated At': item.get('lastModified'),
                        'NVD CVSS3 Vector': vectors,
                    }

                elif self.report_key == ReportsSecureMapping.CONTAINERS:
                    report_data[record_id] = {
                        'Region': cloud_metadata.get('region'),
                        'Provider': cloud_metadata.get('provider'),
                        'Account ID': cloud_metadata.get('accountID'),
                        'Last Seen': cloud_metadata.get('scanTime') if cloud_metadata else item.get('scanTime'),
                        'PackageManager': cloud_metadata.get('packageManager') if cloud_metadata else item.get('packageManager'),
                        'ResourceID': cloud_metadata.get('resourceID'),
                        'NVD CVSS3 Vector': vectors,
                    }

                elif self.report_key == ReportsSecureMapping.HOSTS:
                    report_data[record_id] = {
                        'Hostname': record_id,
                        'Last Seen': item['scanTime'],
                        'Resource Tags': ",".join([label for label in item.get("labels")]),
                        'Ami':  cloud_metadata.get("vmImageID", ""),
                        'NVD CVSS3 Vector': vectors,
                    }

            if len(response_content) < 100:
                break # reached the end of the data

            params['offset'] += 100

        return report_data

    def get_cloud_account_info(self):
        response = api.compose_get_request(
            self.token,
            url_complement="cloud/name",
        )
        only_clouds_id_and_name = {
            cloud_info.get("id"): cloud_info.get("name")
            for cloud_info in response
        }
        return only_clouds_id_and_name

    def get_vms_data(self):
        data = {}
        params = {"limit": 100, "offset": 0}
        while True:
            response = api.compose_console_get_request(
                self.console_token,
                url_complement="cloud/discovery/vms",
                params=params
            )

            if not hasattr(response, "content"):  # check if the response is empty
                break  # no more data to fetch

            response = json.loads(response.content)
            for record in response:
                data[record.get("_id")] = record.get("awsVPCID")

            if len(response) < 100:
                break
            else:
                params["offset"] += 100

        return data

    def get_images_data_for_registry(self):
        images_counts = []
        params = {"offset": 0}
        while True:
            response = api.compose_console_get_request(
                self.console_token,
                url_complement="images",
                params=params
            )

            if not response or not hasattr(response, "content"):  # check if the response is empty
                break # no more data to fetch

            response_content = json.loads(response.content)

            images_counts += [
                {
                    "Image ID": image["id"],
                    "Image In Use Count": image["complianceIssuesCount"] + image["vulnerabilitiesCount"]
                } for image in response_content
            ]

            if len(response_content) < 100:
                break # reached the end of the data

            params['offset'] += 100

        return images_counts

    # report methods
    def get_report_data(self):
        # main function to orchestrate the process of downloading and saving the vulnerability report.

        # get the csv data (api call) and use StringIO to stuff it into a pandas DataFrame
        csv_data = self.download_vulnerability_report()
        csv_data_content = csv_data.content
        dataframe_from_csv = pd.read_csv(StringIO(csv_data_content.decode('utf-8')), dtype=str)
        allowed_severities = ['critical', 'high', 'medium']
        if 'Severity' in dataframe_from_csv.columns:
            dataframe_from_csv = dataframe_from_csv[dataframe_from_csv['Severity'].str.lower().isin(allowed_severities)]
        # scan api call
        cloud_metadata = self.get_scan_info()
        scan_metadata_dataframe = pd.DataFrame.from_dict(cloud_metadata, orient='index').reset_index()

        if scan_metadata_dataframe.empty:
            logging.warning(f"Empty dataframe metadata for {self.report_key}!")

        # columns and dataframe merging
        scan_metadata_dataframe.columns = self.report.get("scan_columns")
        scan_metadata_dataframe = scan_metadata_dataframe[
            [column for column in scan_metadata_dataframe.columns if column not in dataframe_from_csv.columns or column == self.report.get("index_column")]
        ]
        merged_dataframes = pd.merge(dataframe_from_csv, scan_metadata_dataframe, on=self.report.get("index_column"), how='left')

        if False and self.report_key == ReportsSecureMapping.REGISTRY: # currently disabled!
            image_data = self.get_images_data_for_registry()
            image_dataframe = pd.DataFrame(image_data).reset_index(drop=True)
            merged_dataframes = pd.merge(
                image_dataframe, merged_dataframes, on="Image ID", how='right'
            )

        final_dataframe = self.get_final_columns(merged_dataframes)

        # process and save the report, getting the separate DataFrames
        reports = self.save_report_to_csv(final_dataframe)

        return reports

    @staticmethod
    def rename_columns(dataframe):
        dataframe.rename(columns=COLUMNS_RENAMES, inplace=True)
        return dataframe

    def get_final_columns(self, df):
        # choosen columns
        selected_columns = self.report.get("selected_columns")

        # filter out (exclude) any columns that may not exist in the DataFrame
        selected_columns = [column for column in selected_columns if column in df.columns]

        # reorder DataFrame columns as specified in 'selected_columns'
        df = df.loc[:, selected_columns]

        # rename
        df = CWPReportData.rename_columns(df)

        # It maps the 'Type' column (from the raw data) to the 'Package Manager' column for each individual row.
        df['Package Manager'] = df['Type'].apply(self.map_package_type)

        try:
            # check if 'Risk Factors' contains 'Exploit exists - POC' OR 'Exploit exists - in the wild'
            df['Exploit Available'] = df['Risk Factors'].str.contains(
                'Exploit exists - POC|Exploit exists - in the wild', na=False
            )
            # set 'Exploitable' to 'Yes' or 'No'
            df['Exploit Available'] = df['Exploit Available'].map({True: 'YES', False: 'NO'})
        except KeyError as error:
            logging.warning(f"No column: {error}!")
            df['Exploit Available'] = ""

        if self.report_key in (ReportsSecureMapping.IMAGES, ReportsSecureMapping.CONTAINERS):
            # filter out (exclude) rows where 'Namespaces' contains values matching 'kube-*'
            # this is done for administered services AWS EKS if client is running its own cluster this must be commented
            try:
                df = df[~df['Namespaces'].str.contains(r'^kube-', na=False)]
            except KeyError as error:
                logging.warning(f"No column: {error}!")
        elif self.report_key == ReportsSecureMapping.SERVERLESS:
            df = df.loc[df['Vulnerability ID'] != 0]
        elif self.report_key == ReportsSecureMapping.HOSTS:
            df['Resource Public Ipv4'] = df['Resource ID'].apply(
                lambda x: x.split('.')[0].replace('ip-', '').replace('-', '.') if isinstance(x, str) and x.startswith(
                    'ip-') else '')

        date_column = "First Seen"
        try:
            # ensure 'First Seen' is in datetime format for date calculations
            df[date_column] = pd.to_datetime(df[date_column], utc=True, errors='coerce')
            # calculate the age in days since the issue was discovered (First Seen)
            current_date = pd.Timestamp.now(tz='UTC')
            df['Age (Days)'] = (current_date - df[date_column]).dt.days
            df[date_column] = df[date_column].dt.tz_localize(None)
        except KeyError as error:
            logging.warning(f"No date column! Error: {error}")
            df['Age (Days)'] = ""

        df['Resource Type'] = self.report.get("resource_type_column")

        if self.report_key == ReportsSecureMapping.HOSTS:
            df['AWS Account Id'] = df['AWS Account Id'].apply(str)

        # column mapping choosen by the client
        # "account" column
        df.insert(1, 'Account', df.apply(self.get_cloud_accounts, axis=1))

        # "severity" column
        df['Severity'] = df['Severity'].str.upper()

        # irreplicable columns
        all_blank_columns = BLANK_COLUMNS + [column for column in self.report.get("selected_columns") if column in FINAL_REDEBAN_COLUMNS and column not in df.columns and column not in BLANK_COLUMNS]
        for column in all_blank_columns:
            df[column] = ""

        # copied columns
        if self.report_key != ReportsSecureMapping.SERVERLESS:
            try:
                df['Last Updated'] = df['Last Seen']
            except KeyError as error:
                logging.warning(f"Error: {error}!")
                df['Last Updated'] = ""

        try:
            if self.report_key == ReportsSecureMapping.SERVERLESS:
                df['Finding Type'] = "CODE_VULNERABILITY"
            else:
                df['Finding Type'] = df['Vulnerability ID'].isnull().map({True: "", False: "PACKAGE_VULNERABILITY"})
        except KeyError as error:
            logging.warning(f"Error: {error}!")
            df['Finding Type'] = ""

        try:
            df['Fix Available'] = df['Risk Factors'].str.contains(
                "Has fix", na=False
            ).map({True: 'YES', False: 'NO'})
        except KeyError as error:
            logging.warning(f"Error: {error}!")
            df['Fix Available'] = ""

        if self.report_key == ReportsSecureMapping.REGISTRY:
            try:
                df['Resource ID'] = df.apply(self.get_registry_resource_id, axis=1)
            except KeyError as error:
                logging.warning(f"Error: {error}!")
        elif self.report_key == ReportsSecureMapping.SERVERLESS:
            try:
                df['Platform'] = df.apply(self.format_serverless_platform, axis=1)
            except KeyError as error:
                logging.warning(f"Error: {error}!")

            try:
                df['Fixed in Version'] = df.apply(self.get_serverless_fixed_in, axis=1)
            except KeyError as error:
                logging.warning(f"Error: {error}!")

            try:
                df["File Path"] = df.apply(self.get_serverless_file_path, axis=1)
            except KeyError as error:
                logging.warning(f"Error: {error}!")
        elif self.report_key == ReportsSecureMapping.HOSTS:
            try:
                df['Resource Vpc'] = df.apply(self.get_hosts_resource_vpc, axis=1)
            except KeyError as error:
                logging.warning(f"Error: {error}!")

        df['Package Remediation'] = df.apply(self.get_package_remediation, axis=1)

        return df
    
    def get_serverless_file_path(self, row):
        package_name = row.get("Affected Packages")
        package_version = row.get("Package Installed Version")
        filtered_paths = []
        for package_path in row.get("File Path"):
            for package in package_path.get("pkgs"):
                if package.get("name") == package_name and package.get("version") == package_version:
                    filtered_paths.append(
                        f"{package_path.get('pkgsType')}{package.get('path')}"
                    )

        return ", ".join(filtered_paths)

    def get_serverless_fixed_in(self, row):
        if not row['Fixed in Version'] or pd.isna(row['Fixed in Version']):
            return ""
        return f"{row['Affected Packages']}[{str(row['Fixed in Version']).replace('fixed in ', '')}]"

    def format_serverless_platform(self, row):
        return f"{row['Platform']}".lower()

    def get_registry_resource_id(self, row):
        return f"arn:aws:ecr:{row['Region']}:{row['AWS Account Id']}:repository/{row['Repository']}/{row['Resource ID']}"

    def get_cloud_accounts(self, row):
        account_id = row["AWS Account Id"]
        return self.account_names.get(account_id, "")
    
    def map_package_type(self, package_type):
        # Look up the package type in our mapping dictionary.
        mapped_value = REAL_PACKAGE_NAMES.get(str(package_type).lower())
        
        # If the type is not found, print it for debugging and return the generic value.
        if not mapped_value:
            logging.warning(f"DEBUG: Unrecognized package Type found: '{package_type}'")
            return GENERIC_PACKAGE
        
        return mapped_value

    def get_hosts_resource_vpc(self, row):
        resource_id = row["Resource ID"]
        return self.vms_data.get(resource_id, "")
    
    def get_package_remediation(self, row):
        package_manager_type = row.get('Package Manager')
        fixed_in_version_str = row.get('Fixed in Version', '')
        affected_packages_str = row.get('Affected Packages', '')

        if not fixed_in_version_str or pd.isna(fixed_in_version_str) or any(s in str(fixed_in_version_str).lower() for s in ['open', 'notavailable']):
            return ""

        if package_manager_type in ['OS', 'GENERIC']:
            # Normalize the platform string.
            platform_key = row.get('Platform', '').lower().replace('_', '').replace('-', '')
            
            # --- NEW: Flexible "wildcard" search logic ---
            update_command = None
            # Loop through the map in helper.py to find a matching keyword.
            for key, command in OS_COMMAND_MAP.items():
                if key in platform_key:
                    update_command = command
                    break # Stop once we find the first match.
            
            # If no command was found, log a warning and use a generic fallback.
            if not update_command:
                logging.warning(f"Unrecognized OS Platform found: '{row.get('Platform')}'. Using generic 'update' command.")
                update_command = "update"
            # ---------------------------------------------

            remediation_parts = []
            for package_name in affected_packages_str.split(','):
                package_name = package_name.strip()
                if package_name:
                    remediation_parts.append(f"{package_name}[{update_command} {package_name}]")
            return ", ".join(remediation_parts)
        
        else:
            # The logic for application packages remains the same.
            instructional_map = {
                'JAVA': 'Update dependency in build file (e.g., pom.xml or build.gradle)',
                'BINARY': 'Replace binary with fixed version'
            }
            if package_manager_type in instructional_map:
                instruction = instructional_map[package_manager_type]
                return f"{affected_packages_str}[{instruction}]"

            app_command_map = {
                'PYTHON': ('pip install', '{pkg}=={ver}'),
                'NODE': ('npm install', '{pkg}@{ver}'),
                'NPM': ('npm install', '{pkg}@{ver}'),
                'RUBY': ('gem install', '{pkg} -v {ver}'),
                'GO': ('go get', '{pkg}@{ver}'),
            }
            if package_manager_type in app_command_map:
                version_match = re.search(r'[\d\.\-rcv]+', fixed_in_version_str)
                version = version_match.group(0) if version_match else None
                if version and affected_packages_str:
                    base_command, command_template = app_command_map[package_manager_type]
                    remediation_parts = []
                    for package_name in affected_packages_str.split(','):
                        package_name = package_name.strip()
                        if package_name:
                            if package_manager_type == 'GO' and not version.startswith('v'):
                                version = f'v{version}'
                            fix_command = command_template.format(pkg=package_name, ver=version)
                            remediation_parts.append(f"{package_name}[{base_command} {fix_command}]")
                    return ", ".join(remediation_parts)
            
            return f"update to {fixed_in_version_str}"
    
    def save_report_to_csv(self, final_dataframe):
        # process the CSV data and save it to a file, applying necessary transformations.
        files = {}
        for cloud in ["aws"]: #, "azure"
            # separate the DataFrame based on 'Provider' values ('aws' and 'azure')
            if self.report_key == ReportsSecureMapping.REGISTRY:
                dataframe_cloud = final_dataframe
            else:
                dataframe_cloud = final_dataframe[final_dataframe['Provider'] == cloud]

            columns_available = [column for column in FINAL_REDEBAN_COLUMNS if column in dataframe_cloud.columns]
            files[f"scans_{cloud}"] = dataframe_cloud.loc[:, columns_available]

            # disabled!
            if False and self.report_key == ReportsSecureMapping.HOSTS and cloud == "aws":
                # 'Cluster' is empty (NaN), if cluster in empty host is not part of a cluster
                df_aws_empty_cluster = dataframe_cloud[dataframe_cloud['Cluster'].isna()]
                files[f"aws_cluster_empty"] = df_aws_empty_cluster

                # 'Cluster' is not empty, if cluster is not empy host is part of a cluster
                df_aws_not_empty_cluster = dataframe_cloud[dataframe_cloud['Cluster'].notna()]
                files[f"aws_cluster_not_empty"] = df_aws_not_empty_cluster

            if False and self.report_key != ReportsSecureMapping.CONTAINERS: # disabled!
                # create a new DataFrame with the specified columns for detailed pdf report AWS---
                pdf_columns = [
                    'AWS Account Id', 'Severity', 'Description', 'Vulnerability ID',
                    'Exploit Available', "First Seen", 'Region'
                ]
                if self.report_key == ReportsSecureMapping.REGISTRY:
                    pdf_columns.append("Registry")
                elif self.report_key == ReportsSecureMapping.IMAGES or self.report_key == ReportsSecureMapping.HOSTS:
                    pdf_columns.append("Resource ID")
                elif self.report_key == ReportsSecureMapping.SERVERLESS:
                    pdf_columns.append("Platform")

                # create the new DataFrame
                dataframe_detailed_cloud = dataframe_cloud[pdf_columns]
                files[f"detailed_{cloud}"] = dataframe_detailed_cloud

        return files


class CWPReport:
    def __init__(self):
        self.starting_column = 1
        self.starting_row = 5

    def prepare_file(self, file_name, report_dataframe):
        (maximum_row, maximum_columns) = report_dataframe.shape

        report_filename = f"{file_name} - ({datetime.date.today()}).xlsx"
        if file_name.startswith("report_scans_aws"):
            report_filename = f"Escaneo AWS a {datetime.date.today()}.xlsx"

        with pd.ExcelWriter(report_filename, engine="xlsxwriter", engine_kwargs={'options': {'strings_to_urls': False}}) as writer:
            workbook = writer.book
            sheet_name = f"{datetime.date.today()}"
            sheet = workbook.add_worksheet(name=sheet_name)
            report_dataframe.style.set_properties(**{'text-align': 'center'}).to_excel(
                writer,
                sheet_name=sheet_name,
                header=False,
                index=False,
                startcol=self.starting_column,
                startrow=self.starting_row + 1
            )

            # add headers + format
            centered_format = workbook.add_format({'align': 'center'})
            sheet.add_table(
                self.starting_row, self.starting_column, maximum_row + self.starting_row, maximum_columns,
                {
                    "columns": [{"header": column, "header_format": centered_format} for column in report_dataframe.columns],
                    "style": 'Table Style Medium 4'
                }
            )


            title_format = workbook.add_format({'font_size': 35, 'bold': True})
            sheet.write('B4', "Escaneo AWS", title_format)

            # set width from all columns between the 0 index and the maximum_columns - 1 index
            sheet.set_column(0, maximum_columns - 1, width=20)

            images_cells = {
                "B": {"url": "https://pagosrecurrentes.redebandigital.com/assets/images/logo/redeban.png",
                      "options": {'x_scale': 0.39, 'y_scale': 0.39}},
                "E": {"url": "https://www.greatplacetowork.com.co/images/CompaniesCertification/Fotos/Netdata/2024/Logo_actualizado.png",
                      "options": {'x_scale': 0.14, 'y_scale': 0.14, 'y_offset': 10}},
            }
            for cell, information in images_cells.items():
                try:
                    image_data = BytesIO(urlopen(information.get("url")).read())
                except HTTPError:
                    continue
                sheet.insert_image(f"{cell}1", information.get("url"),
                                       {"image_data": image_data, **information.get("options")})

    def get_individual_report(self):
        report_key = ReportsSecureMapping.SERVERLESS
        report = CWPReportData(report_key=report_key)

        data = report.get_report_data()

        for key, file_dataframe in data.items():
            if file_dataframe.empty:
                logging.warning(f"Empty dataframe for {key}!")
            else:
                self.prepare_file(f"{report_key}_report_{key}", file_dataframe)
                logging.info(f"Report ready: {key}!")


    def get_consolidated_report(self):
        reports_mapping = ReportsSecureMapping()
        reports_mapping = [
            getattr(reports_mapping, report) for report in dir(reports_mapping)
            if not report.startswith('__') and report.lower() not in (ReportsSecureMapping.IMAGES, ReportsSecureMapping.CONTAINERS)
        ]

        files_accumulator = {}
        for report_mapping in reports_mapping:
            logging.info(f"Starting: {report_mapping}!")
            report = CWPReportData(report_key=report_mapping)
            data = report.get_report_data()
            for file_key, file_data in data.items():
                if file_key in files_accumulator:
                    try:
                        files_accumulator[file_key] = pd.concat([files_accumulator[file_key], file_data], ignore_index=True, sort=False)
                    except pd.errors.InvalidIndexError as error:
                        logging.error(f"Columns error: {error}!")
                        breakpoint()
                        exit(1)
                else:
                    files_accumulator[file_key] = file_data

        for key, file_dataframe in files_accumulator.items():
            if file_dataframe.empty:
                logging.warning(f"Empty dataframe for {key}!")
            else:
                # empty dataframe with set columns here!

                force_columns_dataframe = pd.DataFrame(columns=FINAL_REDEBAN_COLUMNS)
                final_dataframe = pd.merge(
                    force_columns_dataframe, file_dataframe, how='right'
                )

                self.prepare_file(f"report_{key}", final_dataframe)
                logging.info(f"Report ready: {key} with columns!")


if __name__ == "__main__":
    final_report = CWPReport()
    final_report.get_consolidated_report()
    #final_report.get_individual_report()