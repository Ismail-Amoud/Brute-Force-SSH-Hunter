import re

log_file = "auth.log"
report_file = "ssh_bruteforce_report.txt"

failed_attempts = {}
targeted_users = {}

threshold = 3

with open(log_file, "r") as file:
    for line in file:
        if "Failed password" in line:
            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

            user_match = re.search(r"for (invalid user )?(\w+)", line)

            if ip_match and user_match:
                ip = ip_match.group(1)
                user = user_match.group(2)

                if ip not in failed_attempts:
                    failed_attempts[ip] = 0

                failed_attempts[ip] += 1

                if ip not in targeted_users:
                    targeted_users[ip] = set()

                targeted_users[ip].add(user)

print("\n=== SSH Failed Login Summary ===\n")

for ip, count in failed_attempts.items():
    print(f"{ip} : {count} failed attempts")

print("\n=== Potential Brute Force Activity ===\n")

suspicious_ips = {}

for ip, count in failed_attempts.items():
    if count >= threshold:
        suspicious_ips[ip] = count
        users = ", ".join(targeted_users[ip])
        print(f"ALERT: {ip} generated {count} failed SSH login attempts against user(s): {users}")

with open(report_file, "w") as report:
    report.write("SSH Brute Force Analysis Report\n")
    report.write("===============================\n\n")

    report.write("Failed SSH Login Summary\n")
    report.write("------------------------\n")

    for ip, count in failed_attempts.items():
        report.write(f"{ip} : {count} failed attempts\n")

    report.write("\nPotential Brute Force Activity\n")
    report.write("------------------------------\n")

    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            users = ", ".join(targeted_users[ip])
            report.write(f"ALERT: {ip} generated {count} failed SSH login attempts against user(s): {users}\n")
    else:
        report.write("No brute force activity detected.\n")

print(f"\nReport generated successfully: {report_file}")
