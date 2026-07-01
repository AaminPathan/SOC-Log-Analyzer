failed_count = 0
successful_count = 0
Failed_User = {}
Failed_IP = {}
with open("logs/logs.txt", "r") as file:
    for log in file:
        if "Failed" in log:
            failed_count += 1
            user = log.split()[4].split(":")[1]
            ip = log.split()[5].split(":")[1]
            if user in Failed_User:
                Failed_User[user] += 1
            else:
                Failed_User[user] = 1

            if ip in Failed_IP:
                Failed_IP[ip] += 1
            else:
                Failed_IP[ip] = 1

        if "Success" in log:
            successful_count += 1

print("===== SECURITY REPORT =====\n")
print(f"Total Login Attempts : {failed_count + successful_count}")
print(f"Failed Login Attempts : {failed_count}")
print(f"Successful Login Attempts : {successful_count}")

print("\n====Failed Login By User :=====\n")

for user, count in Failed_User.items():  
    print(f"User : {user} | Failed Attempts : {count}")


print("\n====Failed Login By IP :=====")

for ip, count in Failed_IP.items():
    print(f"IP : {ip} | Failed Attempts : {count}")



print("\n===== ALERTS =====\n")

if failed_count >= 5:
    print("Potential Brute Force : YES")
    print("Severity              : HIGH")
else:
    print("Severity              : Low")
    print("Alert                 : No Brute Force Detected")

