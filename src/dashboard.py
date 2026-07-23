import tkinter as tk
from tkinter import ttk

class Dashboard:
    def __init__(self, dataset):
        self.dataset = dataset
        self.root = tk.Tk()
        self.root.title("DeepSpace CyberShield AI Dashboard")
        self.root.geometry("1200x700")
        self.root.configure(bg="#1E1E1E")
        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self):
        title = tk.Label(self.root,text="DeepSpace CyberShield AI Dashboard",
                         font=("Arial",22,"bold"),bg="#1E1E1E",fg="cyan")
        title.pack(pady=10)

        stats=tk.Frame(self.root,bg="#1E1E1E")
        stats.pack()

        total=len(self.dataset)
        normal=(self.dataset["status"]=="Normal").sum()
        attacks=total-normal

        for i,(txt,color) in enumerate([
            (f"Total Records : {total}","white"),
            (f"Normal : {normal}","lightgreen"),
            (f"Attacks : {attacks}","red")
        ]):
            tk.Label(stats,text=txt,font=("Arial",12,"bold"),
                     bg="#1E1E1E",fg=color).grid(row=0,column=i,padx=20)

        columns=("Source","Relay","Status","Trust","Prediction")
        self.tree=ttk.Treeview(self.root,columns=columns,show="headings",height=18)

        for c in columns:
            self.tree.heading(c,text=c)
            self.tree.column(c,width=180)

        self.tree.pack(fill="both",expand=True,padx=15,pady=15)

        for _,row in self.dataset.iterrows():
            self.tree.insert("", "end", values=(
                row["source"],
                row["relay"],
                row["status"],
                row["trust_score"],
                row["AI_Prediction"]
            ))

        details=tk.LabelFrame(self.root,text="Communication Details",
                              bg="#1E1E1E",fg="cyan",
                              font=("Arial",12,"bold"))
        details.pack(fill="x",padx=15,pady=10)

        labels=["Source","Relay","Status","Trust Score","AI Prediction","Recommendation"]
        self.values=[]
        for i,l in enumerate(labels):
            tk.Label(details,text=l,bg="#1E1E1E",fg="white").grid(row=i,column=0,sticky="w",padx=10,pady=4)
            lab=tk.Label(details,text="-",bg="#1E1E1E",fg="cyan",justify="left")
            lab.grid(row=i,column=1,sticky="w")
            self.values.append(lab)

        self.tree.bind("<<TreeviewSelect>>",self.update_details)

    def update_details(self,event):
        item=self.tree.focus()
        if not item:
            return
        vals=self.tree.item(item)["values"]
        source,relay,status,trust,pred=vals

        self.values[0].config(text=source)
        self.values[1].config(text=relay)
        self.values[2].config(text=status)
        self.values[3].config(text=f"{float(trust):.2f}")

        if pred=="Normal":
            self.values[4].config(text="🟢 Normal",fg="lightgreen")
            rec="Continue Communication\nMission Secure"
        else:
            self.values[4].config(text="🔴 Anomaly",fg="red")
            rec="Disconnect Relay\nNotify Ground Station\nBegin Intrusion Scan"

        self.values[5].config(text=rec,fg="orange")

def launch_dashboard(dataset):
    Dashboard(dataset)
    import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt

class Dashboard:
    def __init__(self, dataset):
        self.dataset = dataset
        self.root = tk.Tk()
        self.root.title("DeepSpace CyberShield AI Dashboard")
        self.root.geometry("900x500")
        self.build()

    def build(self):
        ttk.Button(self.root,text="Attack Pie Chart",command=self.show_pie).pack(pady=8)
        ttk.Button(self.root,text="Trust Bar Chart",command=self.show_bar).pack(pady=8)
        ttk.Button(self.root,text="Refresh",command=self.refresh).pack(pady=8)
        ttk.Button(self.root,text="Export CSV",command=self.export_csv).pack(pady=8)
        ttk.Button(self.root,text="Future PDF Export",command=self.pdf_placeholder).pack(pady=8)

    def show_pie(self):
        counts=self.dataset["status"].value_counts()
        plt.figure(figsize=(5,5))
        plt.pie(counts.values,labels=counts.index,autopct="%1.1f%%")
        plt.title("Attack Distribution")
        plt.show()

    def show_bar(self):
        plt.figure(figsize=(7,4))
        self.dataset.groupby("source")["trust_score"].mean().plot(kind="bar")
        plt.title("Average Trust Score by Mission")
        plt.ylabel("Trust Score")
        plt.tight_layout()
        plt.show()

    def refresh(self):
        messagebox.showinfo("Refresh","Dashboard refreshed successfully.")

    def export_csv(self):
        path=filedialog.asksaveasfilename(defaultextension=".csv",
                                          filetypes=[("CSV","*.csv")])
        if path:
            self.dataset.to_csv(path,index=False)
            messagebox.showinfo("Export","CSV exported successfully.")

    def pdf_placeholder(self):
        messagebox.showinfo("Coming Soon","PDF export will be added in the next version.")

def launch_dashboard(dataset):
    Dashboard(dataset).root.mainloop()