import subprocess
import pandas as pd
import json
import os

# Modify these paths
vol_path = r"PATH\volatility\Volatility3-2.5.0\vol.py"
dump_path = r"PATH\volatility\Dump\Zeus.raw"
out_dir = r"PATH\volatility\Dump\Output"

os.makedirs(out_dir, exist_ok=True)

def run_vol(module, out_name):
    output_path = os.path.join(out_dir, out_name)
    with open(output_path, "w") as f:
        subprocess.run([
            "python", vol_path,
            "-f", dump_path,
            "-r", "json",
            f"windows.{module}"
        ], stdout=f, check=True)
    return output_path

def read_json(path):
    with open(path, "r") as f:
        return pd.json_normalize(json.load(f))

# --- Run modules and collect data ---
features = {}

# pslist
pslist_json = run_vol("pslist", "pslist.json")
pslist_df = read_json(pslist_json)
features["pslist.avg_threads"] = pslist_df["Threads"].mean()

# dlllist
dlllist_json = run_vol("dlllist", "dlllist.json")
dll_df = read_json(dlllist_json)
dll_counts = dll_df.groupby("PID").size()
features["dlllist.ndlls"] = dll_counts.sum()
features["dlllist.avg_dlls_per_proc"] = dll_counts.mean()

# handles
handles_json = run_vol("handles", "handles.json")
h_df = read_json(handles_json)
for obj_type in ["Event", "Thread", "Semaphore", "Timer", "Section", "Mutant"]:
    key = f"handles.n{obj_type.lower()}"
    features[key] = (h_df["Type"] == obj_type).sum()

# svcscan
svc_json = run_vol("svcscan", "svcscan.json")
svc_df = read_json(svc_json)

# Existing feature: total services per process
services_per_proc = svc_df.groupby("PID").size()
features["svcscan.process_services"] = services_per_proc.sum()
shared_services = svc_df.groupby("PID").size()
features["svcscan.shared_process_services"] = shared_services.sum()



# --- Save final features ---
final_df = pd.DataFrame([features])
final_df.to_csv(os.path.join(out_dir, "extracted_features.csv"), index=False)
print(final_df)

