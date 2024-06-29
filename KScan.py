import tkinter as tk
from tkinter import ttk, messagebox
import importlib.util
import os

class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("安全攻防实验室")

        self.label = tk.Label(root, text="Enter URL:")
        self.label.pack()

        self.entry = tk.Entry(root, width=50)
        self.entry.pack()

        self.script_label = tk.Label(root, text="Select Script:")
        self.script_label.pack()

        self.script_options = ["sql_injection_poc.py", "xss_poc.py", "cve_2024_23897_poc.py"]
        self.script_var = tk.StringVar()
        self.script_dropdown = ttk.Combobox(root, textvariable=self.script_var, values=self.script_options)
        self.script_dropdown.pack()

        self.scan_button = tk.Button(root, text="Scan", command=self.scan)
        self.scan_button.pack()

        self.result_text = tk.Text(root, height=20, width=80)
        self.result_text.pack()

    def scan(self):
        url = self.entry.get()
        script = self.script_var.get()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        if not script:
            messagebox.showerror("Error", "Please select a script")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning {url} with {script} script...\n")

        # Run the selected script
        try:
            script_path = os.path.join(os.getcwd(), script)
            spec = importlib.util.spec_from_file_location("poc_script", script_path)
            poc_script = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(poc_script)
            result = poc_script.run(url)
            self.result_text.insert(tk.END, result)
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()
