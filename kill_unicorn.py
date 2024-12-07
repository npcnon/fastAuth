import psutil

def kill_python_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
          
            if 'uvicorn' in proc.info['name'].lower():
                proc.kill() 
                print(f"Killed process {proc.info['name']} with PID {proc.info['pid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

if __name__ == "__main__":
    kill_python_processes()
