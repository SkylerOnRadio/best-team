import argparse
import multiprocessing
import os
import sys
import time

from config import PROJECT_NAME, PROJECT_VERSION, REPORT_ROOT_DIR, C
from engine import scan_log, load_ioc_feed
from utils import resolve_output_dir, make_output_paths, to_file_url, load_sigs
from reporting import (
    report_terminal, report_csv_integrity, 
    report_csv_behavioral, report_json, report_html
)

def main():
    multiprocessing.freeze_support()

    parser = argparse.ArgumentParser(
    description=f"{PROJECT_NAME} v{PROJECT_VERSION}",
    formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("logfile", help="Path to log file (.log, .gz, .bz2 supported)")
                        
    parser.add_argument("--threshold", "-t", type=float, default=300.0,
                        help="Gap threshold in seconds (default: 300)")
    parser.add_argument("--ioc-feed",        type=str,   default=None,
                        help="Path to newline-delimited known-bad IP list")
    parser.add_argument("--compare",         type=str,   default=None,
                        help="Second log file for comparative actor profiling")
    parser.add_argument("--format", "-f",
                        choices=["all", "terminal", "json", "csv", "html"],
                        default="all",
                        help="Output format(s) (default: all)")
    parser.add_argument("--workers", "-w", type=int, default=None, 
                        help="Worker processes (default: 50 percent of CPU threads)")
    parser.add_argument("--cpu-limit", "-c", type=float, default=80.0, 
                        help="Max CPU percent per worker process (default: 80)")
    
    args = parser.parse_args()

    n_workers = args.workers or max(1, (os.cpu_count() or 2) // 2)
    sigs = load_sigs()

    if not os.path.isfile(args.logfile):
        print(f"{C.RED}[!] File not found: {args.logfile}{C.RESET}")
        sys.exit(1)

    out_dirs  = resolve_output_dir()
    out_paths = make_output_paths(out_dirs)

    print(f"\n{C.CYAN}[*] {PROJECT_NAME} v{PROJECT_VERSION}{C.RESET}")
    print(f"{C.DIM}[*] Scanning      : {args.logfile} …{C.RESET}")

    ioc_set = load_ioc_feed(args.ioc_feed)
    if ioc_set:
        print(f"{C.CYAN}[*] IOC feed loaded: {len(ioc_set)} known-malicious IPs{C.RESET}")

    result = scan_log(
        args.logfile, 
        args.threshold,
        ioc_set=frozenset(ioc_set), 
        compare_filepath=args.compare,
        n_workers=n_workers,
        cpu_limit_pct=args.cpu_limit,
        sigs=sigs
    )

    fmt = args.format

    # 1. Output Terminal Dashboard Immediately
    if fmt in ("all", "terminal"):
        report_terminal(result, args.logfile)

    # 2. Compile File Generation Tasks
    tasks = []
    if fmt in ("all", "csv"):
        tasks.append(("CSV Integrity Database", lambda: report_csv_integrity(result, out_paths["csv_integrity"])))
        tasks.append(("CSV Behavioral Matrix", lambda: report_csv_behavioral(result, out_paths["csv_behavioral"])))
    if fmt in ("all", "html"):
        tasks.append(("HTML Visual Dashboard", lambda: report_html(result, args.logfile, out_paths["html"])))
    if fmt in ("all", "json"):
        tasks.append(("JSON Raw Telemetry", lambda: report_json(result, out_paths["json"])))

    # 3. Process File Tasks with Progress Bar
    if tasks:
        if fmt != "terminal":
            print(f"\n{C.CYAN}[*]{C.RESET} Generating Forensic Evidence Files...")
            
        total = len(tasks)
        for i, (name, func) in enumerate(tasks):
            # Print current progress before executing task
            pct = int((i / total) * 100)
            bar_len = 25
            filled = int(bar_len * i / total)
            bar = '█' * filled + '░' * (bar_len - filled)
            sys.stdout.write(f"\r    {C.DIM}[{C.RESET}{C.GREEN}{bar}{C.RESET}{C.DIM}]{C.RESET} {pct:>3}% | {name:<25}")
            sys.stdout.flush()
            
            # Execute File Save
            func()
            
            # Artificial micro-delay so the progress bar is actually visible
            time.sleep(0.15) 

        # Finish to 100%
        bar = '█' * 25
        sys.stdout.write(f"\r    {C.DIM}[{C.RESET}{C.GREEN}{bar}{C.RESET}{C.DIM}]{C.RESET} 100% | {C.GREEN}All files committed to disk.{C.RESET}       \n")
        sys.stdout.flush()

        # Print Output Paths
        print()
        if fmt in ("all", "csv"):
            print(f"📁 {C.BOLD}Integrity CSV{C.RESET}  : {to_file_url(out_paths['csv_integrity'])}")
            print(f"📁 {C.BOLD}Behavioral CSV{C.RESET} : {to_file_url(out_paths['csv_behavioral'])}")
        if fmt in ("all", "html"):
            print(f"🌐 {C.BOLD}Visual Report{C.RESET}  : {to_file_url(out_paths['html'])}")
        if fmt in ("all", "json"):
            print(f"📄 {C.BOLD}JSON Data{C.RESET}      : {to_file_url(out_paths['json'])}\n")

if __name__ == "__main__":
    main()