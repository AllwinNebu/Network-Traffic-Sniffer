import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import time
from datetime import datetime
import SnifferCore

# Set theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class SnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Traffic Sniffer")
        self.geometry("1100x700")
        
        # Data
        self.sniffer = SnifferCore.PacketSniffer()
        self.packets = []
        self.is_capturing = False
        self.start_time = None
        
        # Layout Config
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._create_sidebar()
        self._create_main_area()
        self._create_detail_area()

    def _create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="NET SNIFFER", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Controls
        self.start_btn = ctk.CTkButton(self.sidebar_frame, text="Start Capture", command=self.toggle_capture, fg_color="green", hover_color="darkgreen")
        self.start_btn.grid(row=1, column=0, padx=20, pady=10)

        self.save_btn = ctk.CTkButton(self.sidebar_frame, text="Save to JSON", command=self.save_capture)
        self.save_btn.grid(row=2, column=0, padx=20, pady=10)

        self.clear_btn = ctk.CTkButton(self.sidebar_frame, text="Clear Packets", command=self.clear_packets, fg_color="gray", hover_color="gray30")
        self.clear_btn.grid(row=3, column=0, padx=20, pady=10)
        
        # Stats
        self.packets_count_label = ctk.CTkLabel(self.sidebar_frame, text="Packets: 0")
        self.packets_count_label.grid(row=5, column=0, padx=20, pady=10)
        
        self.ipv4_count_label = ctk.CTkLabel(self.sidebar_frame, text="IPv4: 0", font=ctk.CTkFont(size=12))
        self.ipv4_count_label.grid(row=6, column=0, padx=20, pady=2)
        
        self.ipv6_count_label = ctk.CTkLabel(self.sidebar_frame, text="IPv6: 0", font=ctk.CTkFont(size=12))
        self.ipv6_count_label.grid(row=7, column=0, padx=20, pady=(2, 20))

    def _create_main_area(self):
        # Top Bar (Filter)
        self.top_bar = ctk.CTkFrame(self, corner_radius=0, height=50)
        self.top_bar.grid(row=0, column=1, sticky="ew")
        
        self.filter_label = ctk.CTkLabel(self.top_bar, text="Filter Protocol:")
        self.filter_label.pack(side="left", padx=10)
        
        self.filter_var = ctk.StringVar(value="ALL")
        self.filter_option = ctk.CTkOptionMenu(self.top_bar, values=["ALL", "TCP", "UDP", "ICMP", "IPv6"], variable=self.filter_var)
        self.filter_option.pack(side="left", padx=10)

        # Packet Table (Using Treeview for columnar data)
        # Note: CustomTkinter doesn't have a Treeview, so we use ttk.Treeview with dark theme styling
        
        self.table_frame = ctk.CTkFrame(self)
        self.table_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        
        # Configure Treeview style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", 
                        background="#2b2b2b", 
                        foreground="white", 
                        fieldbackground="#2b2b2b",
                        rowheight=25)
        style.map('Treeview', background=[('selected', '#1f538d')])
        
        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings", selectmode="browse")
        
        # Scrollbar
        self.scrollbar = ctk.CTkScrollbar(self.table_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        
        # Headers
        self.tree.heading("No", text="No.")
        self.tree.column("No", width=50, anchor="center")
        self.tree.heading("Time", text="Time")
        self.tree.column("Time", width=100, anchor="center")
        self.tree.heading("Source", text="Source IP")
        self.tree.column("Source", width=120, anchor="center")
        self.tree.heading("Destination", text="Dest IP")
        self.tree.column("Destination", width=120, anchor="center")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.column("Protocol", width=80, anchor="center")
        self.tree.heading("Length", text="Len")
        self.tree.column("Length", width=60, anchor="center")
        self.tree.heading("Info", text="Info")
        self.tree.column("Info", width=300, anchor="w")

        # Bind click event
        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

    def _create_detail_area(self):
        self.detail_frame = ctk.CTkFrame(self, height=200)
        self.detail_frame.grid(row=2, column=1, padx=10, pady=(0, 10), sticky="ew")
        
        self.detail_label = ctk.CTkLabel(self.detail_frame, text="Packet Details", font=ctk.CTkFont(weight="bold"))
        self.detail_label.pack(anchor="w", padx=10, pady=5)
        
        self.detail_text = ctk.CTkTextbox(self.detail_frame, height=150)
        self.detail_text.pack(fill="both", padx=10, pady=(0, 10))
        self.detail_text.configure(state="disabled")

    def toggle_capture(self):
        if not self.is_capturing:
            filter_proto = self.filter_var.get()
            if filter_proto == "ALL":
                filter_proto = None
                
            self.sniffer.start(packet_callback=self.on_packet_received, 
                               error_callback=self.on_error,
                               filter_protocol=filter_proto)
            self.is_capturing = True
            self.start_btn.configure(text="Stop Capture", fg_color="red", hover_color="darkred")
            self.filter_option.configure(state="disabled")
        else:
            self.sniffer.stop()
            self.is_capturing = False
            self.start_btn.configure(text="Start Capture", fg_color="green", hover_color="darkgreen")
            self.filter_option.configure(state="normal")

    def on_packet_received(self, packet_info):
        self.packets.append(packet_info)
        idx = len(self.packets)
        
        # Extract basic info for the table
        time_str = packet_info['timestamp']
        src = packet_info['source']
        dst = packet_info['destination']
        proto = packet_info['protocol']
        length = packet_info['length']
        
        info = ""
        details = packet_info['details']
        if 'src_port' in details:
            info += f"{details.get('src_port')} -> {details.get('dst_port')} "
        if 'flags' in details:
            flags = [k for k,v in details['flags'].items() if v]
            info += f"[{', '.join(flags)}] "
        if 'type' in details:
            info += f"Type: {details.get('type')} Code: {details.get('code')}"
            
        # Update UI in main thread
        # Note: tkinter isn't thread safe, need to be careful. 
        # But queue/after is better. For simplicity here we might get away with it or use after.
        self.after(0, lambda: self._insert_packet(idx, time_str, src, dst, proto, length, info))

    def _insert_packet(self, idx, time, src, dst, proto, length, info):
        self.tree.insert("", "end", values=(idx, time, src, dst, proto, length, info))
        self.packets_count_label.configure(text=f"Packets: {len(self.packets)}")
        
        # Update protocol counters
        v4_count = sum(1 for p in self.packets if p['version'] == 'IPv4')
        v6_count = len(self.packets) - v4_count
        self.ipv4_count_label.configure(text=f"IPv4: {v4_count}")
        self.ipv6_count_label.configure(text=f"IPv6: {v6_count}")
        
        # Auto scroll
        self.tree.yview_moveto(1)

    def on_packet_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        item = self.tree.item(selected_items[0])
        idx = int(item['values'][0]) - 1
        
        if 0 <= idx < len(self.packets):
            packet = self.packets[idx]
            self.display_packet_details(packet)

    def display_packet_details(self, packet):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        
        # Nicely format the dictionary
        import pprint
        formatted_details = pprint.pformat(packet, indent=2)
        
        self.detail_text.insert("end", formatted_details)
        
        # If there is payload data, show hex view
        if 'details' in packet and 'payload_data' in packet['details']:
            data = packet['details']['payload_data']
            if isinstance(data, bytes):
                self.detail_text.insert("end", "\n\nPayload (Hex):\n")
                hex_str = ' '.join(f'{b:02x}' for b in data)
                self.detail_text.insert("end", hex_str)
        
        self.detail_text.configure(state="disabled")

    def on_error(self, error_msg):
        self.after(0, lambda: messagebox.showerror("Error", error_msg))
        if self.is_capturing:
            self.after(0, self.toggle_capture)

    def clear_packets(self):
        self.packets = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packets_count_label.configure(text="Packets: 0")
        self.ipv4_count_label.configure(text="IPv4: 0")
        self.ipv6_count_label.configure(text="IPv6: 0")
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.configure(state="disabled")

    def save_capture(self):
        if not self.packets:
            messagebox.showwarning("Warning", "No packets to save")
            return
            
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            try:
                # Remove bytes from JSON to make it serializable
                serializable_packets = []
                for p in self.packets:
                    p_copy = p.copy()
                    if 'details' in p_copy and 'payload_data' in p_copy['details']:
                         p_copy['details']['payload_data'] = p_copy['details']['payload_data'].hex()
                    serializable_packets.append(p_copy)
                    
                with open(filename, 'w') as f:
                    json.dump(serializable_packets, f, indent=4)
                messagebox.showinfo("Success", f"Saved {len(self.packets)} packets to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save: {e}")

    def on_closing(self):
        if self.is_capturing:
            self.sniffer.stop()
        self.destroy()

if __name__ == "__main__":
    if not SnifferCore.is_admin():
         messagebox.showerror("Admin Required", "This application requires Administrator privileges to sniff packets.\nPlease run as Administrator.")
    
    app = SnifferApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
