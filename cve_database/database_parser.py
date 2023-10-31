import csv
import statistics
from datetime import datetime

# Database Headers: cve_id, project_name, project_language, affects_multiple, version_introduced, version_patched, cve_publish_date,
# cvss, project_severity_rating, known_exploited, patch_commit, patch_language, patch_path, path_location, location_category,
# nvd_cwe, manual_label, subclass_label, nvd_override, memory_unsafety, primary_advisory, other_references, summary, additional_notes


global_rows = []
filtered_rows = []

lib_count_map = {}
category_count_map = {}
cve_count_total = 0

system_vuln_lifetimes = []

project_name_to_file = {
	'OpenSSL': 'openssl',
	'GnuTLS': 'gnutls',
	'Mozilla NSS': 'nss',
	'Botan': 'botan'
}


def sort_dict(unsorted_dict):
	sorted_dict = dict(sorted(unsorted_dict.items(), key=lambda elem: elem[1], reverse=True))
	return sorted_dict


def print_lifetime_statistics(lifetime_data):
    print('CVEs with full version information: ' + str(len(lifetime_data)))

    avgCVELifetime = statistics.mean(lifetime_data)
    print('Average: ' + str(avgCVELifetime/365))

    medianCVELifetime = statistics.median(lifetime_data)
    print('Median: ' + str(medianCVELifetime/365))

    sampleStdDev = statistics.stdev(lifetime_data)
    print('Sample standard deviation: ' + str(sampleStdDev/365))

    populationStdDev = statistics.pstdev(lifetime_data)
    print('Population standard deviation: ' + str(populationStdDev/365))


def get_product_versions(systemName):
    with open('../version_datasets/' + systemName + '_versions.csv') as f:
    	lines = f.readlines()
    separated_lines = [x.split(',') for x in lines]

    product_versions = {}
    for line in separated_lines:
    	version_num = line[0].strip()

    	version_date = line[1].strip()
    	product_versions[version_num] = version_date

    return product_versions


def calculate_lifetime(date_introduced, date_patched):
    try:
        date_format = "%m/%d/%Y"
        if (date_introduced and date_patched):
            a = datetime.strptime(date_introduced, date_format)
            b = datetime.strptime(date_patched, date_format)
            delta = b - a
            
            if (delta.days <= 0):
                return -1
            
            system_vuln_lifetimes.append(delta.days)
            #allVulnLifetimes.append(delta.days)
            return 1
    except ValueError:
        return -1


def get_lifetimes(rows):
	lifetime_systems = ['openssl', 'gnutls', 'nss', 'botan']

	for system in lifetime_systems:
		print(system)
		versions_to_dates = get_product_versions(system)

		for row in rows:
			project_name = row[1].strip()

			if project_name in project_name_to_file and project_name_to_file[project_name] == system:
				version_introduced = row[4].strip()
				version_patched = row[5].strip()

				version_introduced_date = ''
				version_patched_date = ''

				if version_introduced != '-' and version_patched != '-':
					if version_patched != 'N':
						if version_introduced in versions_to_dates:
							version_introduced_date = versions_to_dates[version_introduced].strip()
						if version_patched in versions_to_dates:
							version_patched_date = versions_to_dates[version_patched].strip()

					if version_introduced_date and version_patched_date:
						return_val = calculate_lifetime(version_introduced_date, version_patched_date)
						if return_val == -1:
							print('Error calculating vulnerability lifetime for: ', row[0])

		print_lifetime_statistics(system_vuln_lifetimes)
		print('\n')
		system_vuln_lifetimes.clear()


def get_location(rows):
	locations = {}

	for row in rows:
		location_cat = row[14]

		if location_cat and location_cat != '-':
			if location_cat in locations:
				locations[location_cat] += 1
			else:
				locations[location_cat] = 0

	print(locations)


def get_crypto_cve_types(rows):
	crypto_type_counts = {}

	for row in rows:
		category_name = row[16].strip()
		if category_name == "Cryptographic Issue":
			sub_category = row[17].strip()

			if sub_category in crypto_type_counts:
				crypto_type_counts[sub_category] += 1
			else:
				crypto_type_counts[sub_category] = 1

	sorted_crypto_types = sort_dict(crypto_type_counts)
	print(sorted_crypto_types)


def get_input_validation(rows):
	input_val_count = 0
	for row in rows:
		cwe = row[15].strip()
		if cwe == "CWE-20: Improper Input Validation":
			input_val_count += 1

	print('Input Validation count:', input_val_count)


def get_patch_commit_percentage(rows):
	patch_commit_count = 0
	for row in rows:
		patch_commit = row[11].strip()
		if patch_commit != '-':
			patch_commit_count += 1

	print('Patch commit count: ', patch_commit_count)


def get_no_cwe(rows):
	no_label_count = 0

	for row in rows:
		cwe = row[15].strip()
		if cwe.strip() == '-':
			no_label_count += 1

	print('CVEs with no NVD CWE label: ', no_label_count)


def get_relabeled(rows):
	override_count = 0

	for row in rows:
		override_flag = row[18].strip()
		if override_flag == "Y":
			override_count += 1

	print('Number of NVD overrides:', override_count)


def get_side_channel_cwes(rows):
	sc_cwes = []
	for row in rows:
		category_name = row[16].strip()
		if category_name == "Side Channel":
			# Get official CWE label:
			cwes = row[15].split(";")
			for cwe in cwes:
				if cwe != "-":
					sc_cwes.append(cwe.strip())
	unique_cwes = set(sc_cwes)

	print('Unique CWEs in Side Channel Attacks:', len(unique_cwes))
	print(unique_cwes)


def get_mem_safety_from_mem_management(rows):
	non_mem_safe_categories = ['Memory Exhaustion', 'Infinite Loop', 'Infinite Recursion']
	mem_safety_count = 0
	mem_management_count = 0

	for row in rows:
		category_name = row[16].strip()
		if category_name == "Memory Management":
			mem_management_count += 1
			sub_category = row[17].strip()
			if sub_category not in non_mem_safe_categories:
				mem_safety_count += 1

	print('Memory Management issues: ', mem_management_count)
	print('Memory safety-related issues within Memory Management: ', mem_safety_count)


def get_memory_unsafety(rows):
	y = 0
	n = 0

	for row in rows:
		memory_flag = row[19].strip()
		if memory_flag.strip() == 'Y':
			y += 1
		if memory_flag.strip() == 'N':
			n += 1
		# Add sanity check to include '-' possibility

	print('Caused by memory unsafety: ', y)
	print('Unrelated: ', n)
	print('Total C/C++ vulnerabilities: ', y + n)


def get_category_labels(rows):
	for row in rows:
		category_name = row[16].strip() 	# 'manual_label'

		if category_name in category_count_map.keys():
			category_count_map[category_name] += 1
		else:
			category_count_map[category_name] = 1

	sorted_cat_count = sort_dict(category_count_map)

	for category in sorted_cat_count:
		print(category, ':', sorted_cat_count[category])

	# Add sanity check assert that total is total number of CVEs


def print_overall_cve_counts(total_count):
	for lib in lib_count_map:
		lib_cve_count = lib_count_map[lib]
		print(lib, ':', lib_cve_count)

	print('Total Count: ', total_count)


def get_lib_cve_counts(rows):
	# To get individual library counts:e
	for row in global_rows:
		lib_name = row[1].strip()

		if lib_name in lib_count_map.keys():
			lib_count_map[lib_name] += 1
		else:
			lib_count_map[lib_name] = 1

	# Use list with duplicates removed to obtain overall total:
	print_overall_cve_counts(len(filtered_rows))


def remove_duplicates():
	# If a CVE is listed under multiple projects, use the first instance in classifications
	# (since they are all the same type label anyway).
	seen_cves = []
	duplicates = 0

	for row in global_rows:
		cve_id = row[0].strip()
		if cve_id in seen_cves:
			duplicates += 1
		if cve_id not in seen_cves:
			seen_cves.append(cve_id)
			filtered_rows.append(row)


def run_experiments():
	# Read in CSV:
	with open('crypto_lib_cve_database.csv', 'r') as cve_db:
		db_reader = csv.reader(cve_db, delimiter=',') # can add delimiter

		# Extract header
		header = []
		header = next(db_reader)

		for row in db_reader:
			global_rows.append(row)

	cve_db.close()

	remove_duplicates()

	# Edit the function calls below based on desired experiment.
	# Use filtered_rows to use the list with duplicate CVEs removed, and global_rows to use the list as-is
	# (i.e. the raw NVD list with no duplicates removed).

	#get_lib_cve_counts(global_rows)

	get_lifetimes(global_rows)

	# print('\n')
	# get_category_labels(filtered_rows)

	# print('\n')
	#get_side_channel_cwes(filtered_rows)

	
run_experiments()





