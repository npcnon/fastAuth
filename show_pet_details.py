import psutil

def print_pet_process_details():
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_times', 'status']):
        try:
            if 'pet' in proc.info['name'].lower():
                print(f"Process Details for {proc.info['name']} (PID {proc.info['pid']}):")
                print(f"  - Username: {proc.info['username']}")
                print(f"  - Status: {proc.info['status']}")
                print(f"  - Memory Info: {proc.info['memory_info']}")
                print(f"  - CPU Times: {proc.info['cpu_times']}")
                print(f"  - Parent PID: {proc.parent().pid if proc.parent() else 'N/A'}")
                print(f"  - Command Line: {proc.cmdline()}")
                print("-" * 50)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            print(f"Error with process {proc.info['pid']}: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    print_pet_process_details()
