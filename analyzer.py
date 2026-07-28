import hashlib
import json
import os

from datetime import datetime
from collections import defaultdict


# ============================================================
# CONFIGURATION
# ============================================================

METADATA_FILE = "analysis_metadata.json"
REPORT_FILE = "Security_Report.txt"
RESULTS_FILE = "analysis_results.json"


# Detection configuration

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW = 60

PASSWORD_SPRAY_THRESHOLD = 3
PASSWORD_SPRAY_TIME_WINDOW = 300


# ============================================================
# LOG PARSER
# ============================================================

def parse_log(log):
    """
    Extracts timestamp, status, username, and IP
    from one log line.
    """

    parts = log.split()

    timestamp = None
    status = None
    user = None
    ip = None


    # --------------------------------------------------------
    # Parse timestamp
    # --------------------------------------------------------

    try:

        timestamp_text = parts[0] + " " + parts[1]

        timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )

    except (IndexError, ValueError):

        timestamp = None


    # --------------------------------------------------------
    # Parse remaining fields
    # --------------------------------------------------------

    for part in parts:

        if part.startswith("User:"):

            user = part.split(":", 1)[1]


        elif part.startswith("IP:"):

            ip = part.split(":", 1)[1]


        elif part in ("Failed", "Success"):

            status = part


    return timestamp, status, user, ip


# ============================================================
# FILE HASH
# ============================================================

def calculate_file_hash(file_path):
    """
    Creates a SHA-256 hash of a file.
    """

    with open(file_path, "rb") as file:

        file_content = file.read()


    return hashlib.sha256(
        file_content
    ).hexdigest()


# ============================================================
# DUPLICATE ANALYSIS CHECK
# ============================================================

def already_analyzed(current_hash):
    """
    Checks whether the same data was already analyzed.
    """

    if not os.path.exists(METADATA_FILE):

        return False


    with open(METADATA_FILE, "r") as file:

        metadata = json.load(file)


    previous_hash = metadata.get(
        "last_analyzed_hash"
    )


    return current_hash == previous_hash


# ============================================================
# BRUTE FORCE DETECTION
# ============================================================

def detect_brute_force(events_by_ip):
    """
    Detects multiple failed login attempts
    from the same IP within a short time window.
    """

    brute_force_alerts = []


    for ip, events in events_by_ip.items():

        events = sorted(

            events,

            key=lambda event:
            event["timestamp"]

        )


        for start_index in range(
            len(events)
        ):

            attempts = 1


            for next_index in range(

                start_index + 1,

                len(events)

            ):

                time_difference = (

                    events[next_index]["timestamp"]

                    -

                    events[start_index]["timestamp"]

                ).total_seconds()


                if (

                    time_difference

                    <=

                    BRUTE_FORCE_TIME_WINDOW

                ):

                    attempts += 1


                else:

                    break


            if (

                attempts

                >=

                BRUTE_FORCE_THRESHOLD

            ):

                brute_force_alerts.append({

                    "ip": ip,

                    "attempts": attempts,

                    "time_window_seconds":
                    BRUTE_FORCE_TIME_WINDOW

                })


                break


    return brute_force_alerts


# ============================================================
# PASSWORD SPRAYING DETECTION
# ============================================================

def detect_password_spraying(events_by_ip):
    """
    Detects one IP attempting to log in
    to multiple usernames within a time window.
    """

    password_spray_alerts = []


    for ip, events in events_by_ip.items():

        events = sorted(

            events,

            key=lambda event:
            event["timestamp"]

        )


        for start_index in range(

            len(events)

        ):

            unique_users = set()


            for next_index in range(

                start_index,

                len(events)

            ):

                time_difference = (

                    events[next_index]["timestamp"]

                    -

                    events[start_index]["timestamp"]

                ).total_seconds()


                if (

                    time_difference

                    <=

                    PASSWORD_SPRAY_TIME_WINDOW

                ):

                    unique_users.add(

                        events[next_index]["user"]

                    )


                else:

                    break


            if (

                len(unique_users)

                >=

                PASSWORD_SPRAY_THRESHOLD

            ):

                password_spray_alerts.append({

                    "ip": ip,

                    "unique_users":
                    list(unique_users),

                    "user_count":
                    len(unique_users),

                    "time_window_seconds":
                    PASSWORD_SPRAY_TIME_WINDOW

                })


                break


    return password_spray_alerts


# ============================================================
# ANALYZE LOG TEXT
# ============================================================

def analyze_logs(log_text):
    """
    Main analysis engine.

    Receives log text and returns
    structured analysis results.
    """

    failed_count = 0
    successful_count = 0
    malformed_count = 0


    failed_users = defaultdict(int)

    failed_ips = defaultdict(int)


    events_by_ip = defaultdict(list)


    # --------------------------------------------------------
    # Process each log line
    # --------------------------------------------------------

    for log in log_text.splitlines():

        # Ignore empty lines

        if not log.strip():

            continue


        timestamp, status, user, ip = parse_log(log)


        # ----------------------------------------------------
        # Detect malformed log
        # ----------------------------------------------------

        if (

            timestamp is None

            or status is None

            or user is None

            or ip is None

        ):

            malformed_count += 1

            continue


        # ----------------------------------------------------
        # Failed login
        # ----------------------------------------------------

        if status == "Failed":

            failed_count += 1


            failed_users[user] += 1


            failed_ips[ip] += 1


            events_by_ip[ip].append({

                "timestamp": timestamp,

                "user": user

            })


        # ----------------------------------------------------
        # Successful login
        # ----------------------------------------------------

        elif status == "Success":

            successful_count += 1


    # --------------------------------------------------------
    # Highest failed user
    # --------------------------------------------------------

    highest_failed_user = None

    highest_failed_attempts = 0


    if failed_users:

        highest_failed_user = max(

            failed_users,

            key=failed_users.get

        )


        highest_failed_attempts = (

            failed_users[

                highest_failed_user

            ]

        )


    # --------------------------------------------------------
    # Most suspicious IP
    # --------------------------------------------------------

    most_suspicious_ip = None

    most_suspicious_attempts = 0


    if failed_ips:

        most_suspicious_ip = max(

            failed_ips,

            key=failed_ips.get

        )


        most_suspicious_attempts = (

            failed_ips[

                most_suspicious_ip

            ]

        )


    # --------------------------------------------------------
    # Run detections
    # --------------------------------------------------------

    brute_force_alerts = (

        detect_brute_force(

            events_by_ip

        )

    )


    password_spray_alerts = (

        detect_password_spraying(

            events_by_ip

        )

    )


    # --------------------------------------------------------
    # Create result object
    # --------------------------------------------------------

    analysis_results = {

        "summary": {

            "total_login_attempts":

            failed_count

            +

            successful_count,


            "failed_login_attempts":

            failed_count,


            "successful_login_attempts":

            successful_count,


            "malformed_log_entries":

            malformed_count

        },


        "failed_logins_by_user":

        dict(failed_users),


        "failed_logins_by_ip":

        dict(failed_ips),


        "highest_failed_user": {

            "username":

            highest_failed_user,


            "failed_attempts":

            highest_failed_attempts

        },


        "most_suspicious_ip": {

            "ip":

            most_suspicious_ip,


            "failed_attempts":

            most_suspicious_attempts

        },


        "detections": {

            "brute_force": {

                "detected":

                len(

                    brute_force_alerts

                )

                > 0,


                "alerts":

                brute_force_alerts

            },


            "password_spraying": {

                "detected":

                len(

                    password_spray_alerts

                )

                > 0,


                "alerts":

                password_spray_alerts

            }

        }

    }


    return analysis_results


# ============================================================
# SAVE JSON RESULTS
# ============================================================

def save_results(results):
    """
    Saves analysis results as JSON.
    """

    with open(

        RESULTS_FILE,

        "w"

    ) as file:

        json.dump(

            results,

            file,

            indent=4,

            default=str

        )


# ============================================================
# GENERATE HUMAN-READABLE REPORT
# ============================================================

def generate_report(results):

    summary = results["summary"]

    failed_users = results[
        "failed_logins_by_user"
    ]

    failed_ips = results[
        "failed_logins_by_ip"
    ]

    highest_user = results[
        "highest_failed_user"
    ]

    suspicious_ip = results[
        "most_suspicious_ip"
    ]

    detections = results[
        "detections"
    ]


    with open(

        REPORT_FILE,

        "w"

    ) as report_file:


        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        report_file.write(

            "===== SECURITY REPORT =====\n\n"

        )


        report_file.write(

            f"Total Login Attempts : "

            f"{summary['total_login_attempts']}\n"

        )


        report_file.write(

            f"Failed Login Attempts : "

            f"{summary['failed_login_attempts']}\n"

        )


        report_file.write(

            f"Successful Login Attempts : "

            f"{summary['successful_login_attempts']}\n"

        )


        report_file.write(

            f"Malformed Log Entries : "

            f"{summary['malformed_log_entries']}\n"

        )


        # ----------------------------------------------------
        # Failed logins by user
        # ----------------------------------------------------

        report_file.write(

            "\n==== FAILED LOGIN BY USER ====\n\n"

        )


        for user, count in failed_users.items():

            report_file.write(

                f"User : {user} | "

                f"Failed Attempts : {count}\n"

            )


        report_file.write(

            f"\nUser with Highest Failed Attempts : "

            f"{highest_user['username']} | "

            f"Failed Attempts : "

            f"{highest_user['failed_attempts']}\n"

        )


        # ----------------------------------------------------
        # Failed logins by IP
        # ----------------------------------------------------

        report_file.write(

            "\n===== FAILED LOGIN BY IP =====\n\n"

        )


        for ip, count in failed_ips.items():

            report_file.write(

                f"IP : {ip} | "

                f"Failed Attempts : {count}\n"

            )


        report_file.write(

            f"\nMost Suspicious IP : "

            f"{suspicious_ip['ip']} | "

            f"Failed Attempts : "

            f"{suspicious_ip['failed_attempts']}\n"

        )


        # ----------------------------------------------------
        # Alerts
        # ----------------------------------------------------

        report_file.write(

            "\n===== ALERTS =====\n\n"

        )


        brute_force = detections[

            "brute_force"

        ]


        if brute_force["detected"]:

            report_file.write(

                "Potential Brute Force : YES\n"

            )


            for alert in (

                brute_force["alerts"]

            ):

                report_file.write(

                    f"IP : {alert['ip']} | "

                    f"Attempts : "

                    f"{alert['attempts']} | "

                    f"Window : "

                    f"{alert['time_window_seconds']} "

                    f"seconds\n"

                )


        else:

            report_file.write(

                "Potential Brute Force : NO\n"

            )


        password_spraying = detections[

            "password_spraying"

        ]


        if password_spraying["detected"]:

            report_file.write(

                "\nPotential Password Spraying : YES\n"

            )


            for alert in (

                password_spraying["alerts"]

            ):

                report_file.write(

                    f"IP : {alert['ip']} | "

                    f"Unique Users : "

                    f"{alert['user_count']}\n"

                )


        else:

            report_file.write(

                "\nPotential Password Spraying : NO\n"

            )


# ============================================================
# TEXT INPUT
# ============================================================

def get_text_input():

    print(

        "\nPaste your log data."

    )


    print(

        "Type END on a new line "

        "when finished:\n"

    )


    lines = []


    while True:

        line = input()


        if line == "END":

            break


        lines.append(line)


    return "\n".join(lines)


# ============================================================
# FILE INPUT
# ============================================================

def get_file_input():

    file_path = input(

        "Enter log file path: "

    )


    if not os.path.exists(file_path):

        print(

            "File does not exist."

        )

        return None


    with open(

        file_path,

        "r"

    ) as file:

        return file.read()


# ============================================================
# INPUT SELECTION
# ============================================================

def get_log_input():

    print(

        "\nChoose input method:"

    )


    print(

        "1. Paste log text"

    )


    print(

        "2. Analyze log file"

    )


    choice = input(

        "\nEnter choice: "

    )


    if choice == "1":

        return get_text_input()


    elif choice == "2":

        return get_file_input()


    else:

        print(

            "Invalid choice."

        )

        return None


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    log_text = get_log_input()


    if not log_text:

        print(

            "No log data provided."

        )

        return


    # --------------------------------------------------------
    # Analyze logs
    # --------------------------------------------------------

    results = analyze_logs(

        log_text

    )


    # --------------------------------------------------------
    # Save results
    # --------------------------------------------------------

    save_results(

        results

    )


    # --------------------------------------------------------
    # Generate report
    # --------------------------------------------------------

    generate_report(

        results

    )


    print(

        "\nAnalysis completed successfully."

    )


    print(

        f"Results saved to: "

        f"{RESULTS_FILE}"

    )


    print(

        f"Report saved to: "

        f"{REPORT_FILE}"

    )


if __name__ == "__main__":

    main()