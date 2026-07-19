import hashlib
import json
import os
def calculate_file_hash(file_path):
    with open(file_path, "rb") as file:
        file_content = file.read()
    file_hash = hashlib.sha256(file_content)
    return file_hash.hexdigest()

log_file = "logs/logs.txt"
current_hash = calculate_file_hash(log_file)

if os.path.exists("analysis_metadata.json"):
    with open("analysis_metadata.json", "r") as file:
        metadata = json.load(file)

    previous_hash = metadata["last_analyzed_hash"]

    if current_hash == previous_hash:
        print("Same log file already analyzed. Skipping analysis.")
        exit()

report_file = open("Security_Report.txt", "w")
failed_count = 0
successful_count = 0
failed_User = {}
failed_IP = {}
highest_failed_user = ""
highest_failed_attempts = 0
ip_user=""
ip_attempts=0
def log_report(*args,**kwargs):
    print(*args,**kwargs)
    print(*args,file=report_file,**kwargs)


with open("logs/logs.txt", "r") as file:
    for log in file:
        if "Failed" in log:
            failed_count += 1
            user = log.split()[3].split(":")[1]
            ip = log.split()[4].split(":")[1]
            if user in failed_User:
                failed_User[user] += 1
            else:
                failed_User[user] = 1

            if ip in failed_IP:
                failed_IP[ip] += 1
            else:
                failed_IP[ip] = 1

        if "Success" in log:
            successful_count += 1

log_report("===== SECURITY REPORT =====\n")
log_report(f"Total Login Attempts : {failed_count + successful_count}")
log_report(f"Failed Login Attempts : {failed_count}")
log_report(f"Successful Login Attempts : {successful_count}")

log_report("\n====Failed Login By User :=====\n")

for user, count in failed_User.items():  
    log_report(f"User : {user} | Failed Attempts : {count}")
    if count > highest_failed_attempts:
        highest_failed_attempts = count
        highest_failed_user = user
log_report(f"\nUser with Highest Failed Attempts : {highest_failed_user} | Failed Attempts : {highest_failed_attempts}")

log_report("\n====Failed Login By IP :=====")

for ip, count in failed_IP.items():
    log_report(f"IP : {ip} | Failed Attempts : {count}")
    if count> ip_attempts:
        ip_attempts=count
        ip_user= ip
log_report(f"\n Most Suspicious IP : {ip_user} | Failed Attempts : {ip_attempts}")


log_report("\n===== ALERTS =====\n")


if failed_count >= 5:
    log_report("Potential Brute Force : YES")
    log_report("Severity              : HIGH")
else:
    log_report("Severity              : Low")
    log_report("Alert                 : No Brute Force Detected")

report_file.close()
metadata = {
    "last_analyzed_hash": current_hash
}
with open("analysis_metadata.json", "w") as file:
    json.dump(metadata, file, indent=4)

