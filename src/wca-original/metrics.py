#!/usr/bin/env python3

import os
import glob
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['figure.figsize'] = (14, 10)
plt.rcParams['font.size'] = 10


def load_metrics_data(results_dir: str) -> dict:
    csv_pattern = os.path.join(results_dir, "wca_metrics_node*.csv")
    csv_files = sorted(glob.glob(csv_pattern))

    if not csv_files:
        print(f"No CSV files found matching: {csv_pattern}")
        return {}

    data = {}
    for csv_file in csv_files:
        filename = os.path.basename(csv_file)
        try:
            node_id = int(filename.replace("wca_metrics_node", "").replace(".csv", ""))
        except ValueError:
            continue

        try:
            df = pd.read_csv(csv_file, comment='#')
            if not df.empty:
                data[node_id] = df
                print(f"Loaded {len(df)} records from node {node_id}")
        except Exception as e:
            print(f"Warning: Could not parse {csv_file}: {e}")

    return data


def plot_energy_consumption(data: dict, output_dir: str = None):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))

    colors = plt.cm.tab10.colors

    for node_id, df in sorted(data.items()):
        if 'time' in df.columns and 'energy_consumed' in df.columns:
            color = colors[node_id % len(colors)]
            ax1.plot(df['time'], df['energy_consumed'],
                     label=f'Node {node_id}', color=color, linewidth=1.5)

    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('Energy Consumed (J)')
    ax1.set_title('Energy Consumption Over Time (Per Node)')
    ax1.legend(loc='upper left', ncol=2, fontsize=8)
    ax1.grid(True, alpha=0.3)

    all_times = set()
    for df in data.values():
        if 'time' in df.columns:
            all_times.update(df['time'].tolist())

    times = sorted(all_times)
    total_energy = []

    for t in times:
        total = 0
        for df in data.values():
            if 'time' in df.columns and 'energy_consumed' in df.columns:
                mask = df['time'] <= t
                if mask.any():
                    total += df.loc[mask, 'energy_consumed'].iloc[-1]
        total_energy.append(total)

    ax2.plot(times, total_energy, 'b-', linewidth=2)
    ax2.fill_between(times, total_energy, alpha=0.3)
    ax2.set_xlabel('Time (s)')
    ax2.set_ylabel('Total Energy Consumed (J)')
    ax2.set_title('Total Network Energy Consumption Over Time')
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()

    if output_dir:
        filepath = os.path.join(output_dir, 'energy_consumption.png')
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        print(f"Saved: {filepath}")

    return fig


def plot_ch_duration(data: dict, output_dir: str = None):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10))

    colors = plt.cm.tab10.colors

    for node_id, df in sorted(data.items()):
        if 'time' in df.columns and 'ch_duration_cumulative' in df.columns:
            color = colors[node_id % len(colors)]
            ax1.plot(df['time'], df['ch_duration_cumulative'],
                     label=f'Node {node_id}', color=color, linewidth=1.5)

    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('Cumulative CH Duration (s)')
    ax1.set_title('Cluster Head Duration Over Time (Per Node)')
    ax1.legend(loc='upper left', ncol=2, fontsize=8)
    ax1.grid(True, alpha=0.3)

    node_ids = sorted(data.keys())

    all_times = set()
    for df in data.values():
        if 'time' in df.columns:
            all_times.update(df['time'].tolist())
    times = sorted(all_times)

    for idx, node_id in enumerate(node_ids):
        df = data[node_id]
        if 'time' in df.columns and 'is_ch' in df.columns:
            for _, row in df.iterrows():
                if row['is_ch'] == 1:
                    # Draw a bar for this time period
                    ax2.barh(idx, 10, left=row['time'] - 5, height=0.8,
                             color=colors[node_id % len(colors)], alpha=0.8)

    ax2.set_yticks(range(len(node_ids)))
    ax2.set_yticklabels([f'Node {n}' for n in node_ids])
    ax2.set_xlabel('Time (s)')
    ax2.set_title('Cluster Head Status Timeline (colored = CH active)')
    ax2.grid(True, axis='x', alpha=0.3)

    plt.tight_layout()

    if output_dir:
        filepath = os.path.join(output_dir, 'ch_duration.png')
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        print(f"Saved: {filepath}")

    return fig


def plot_ch_selections(data: dict, output_dir: str = None):
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    colors = plt.cm.tab10.colors

    ax1 = axes[0, 0]
    for node_id, df in sorted(data.items()):
        if 'time' in df.columns and 'ch_selections_cumulative' in df.columns:
            color = colors[node_id % len(colors)]
            ax1.plot(df['time'], df['ch_selections_cumulative'],
                     label=f'Node {node_id}', color=color, linewidth=1.5, marker='o', markersize=3)

    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('Cumulative CH Selections')
    ax1.set_title('CH Selection Count Over Time (Per Node)')
    ax1.legend(loc='upper left', ncol=2, fontsize=8)
    ax1.grid(True, alpha=0.3)

    ax2 = axes[0, 1]

    all_times = set()
    for df in data.values():
        if 'time' in df.columns:
            all_times.update(df['time'].tolist())
    times = sorted(all_times)

    total_reselections = []
    for t in times:
        total = 0
        for df in data.values():
            if 'time' in df.columns and 'ch_reselections_cumulative' in df.columns:
                mask = df['time'] <= t
                if mask.any():
                    total = max(total, df.loc[mask, 'ch_reselections_cumulative'].iloc[-1])
        total_reselections.append(total)

    ax2.plot(times, total_reselections, 'r-', linewidth=2, marker='s', markersize=4)
    ax2.fill_between(times, total_reselections, alpha=0.3, color='red')
    ax2.set_xlabel('Time (s)')
    ax2.set_ylabel('Total CH Reselections')
    ax2.set_title('Total Cluster Head Reselections Over Time')
    ax2.grid(True, alpha=0.3)

    ax3 = axes[1, 0]
    node_ids = sorted(data.keys())
    final_selections = []

    for node_id in node_ids:
        df = data[node_id]
        if 'ch_selections_cumulative' in df.columns and not df.empty:
            final_selections.append(df['ch_selections_cumulative'].iloc[-1])
        else:
            final_selections.append(0)

    bars = ax3.bar(range(len(node_ids)), final_selections,
                   color=[colors[n % len(colors)] for n in node_ids])
    ax3.set_xticks(range(len(node_ids)))
    ax3.set_xticklabels([f'N{n}' for n in node_ids])
    ax3.set_xlabel('Node ID')
    ax3.set_ylabel('Times Became CH')
    ax3.set_title('Total CH Selections Per Node')
    ax3.grid(True, axis='y', alpha=0.3)

    for bar, val in zip(bars, final_selections):
        if val > 0:
            ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                     str(int(val)), ha='center', va='bottom', fontsize=9)

    ax4 = axes[1, 1]
    ax4.axis('off')

    total_selections = sum(final_selections)
    total_resel = total_reselections[-1] if total_reselections else 0
    avg_selections = np.mean(final_selections) if final_selections else 0
    max_selections = max(final_selections) if final_selections else 0

    summary_text = f"""
    CH SELECTION SUMMARY
    {'='*30}
    
    Total CH selections: {total_selections}
    Total CH reselections: {int(total_resel)}
    
    Average selections/node: {avg_selections:.2f}
    Max selections (single node): {int(max_selections)}
    
    Nodes that became CH: {sum(1 for s in final_selections if s > 0)}/{len(node_ids)}
    """

    ax4.text(0.1, 0.9, summary_text, transform=ax4.transAxes,
             fontsize=12, verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))

    plt.tight_layout()

    if output_dir:
        filepath = os.path.join(output_dir, 'ch_selections.png')
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        print(f"Saved: {filepath}")

    return fig


def plot_udp_packets(data: dict, output_dir: str = None):
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    colors = plt.cm.tab10.colors

    ax1 = axes[0, 0]
    for node_id, df in sorted(data.items()):
        if 'time' in df.columns and 'udp_packets_sent' in df.columns:
            color = colors[node_id % len(colors)]
            ax1.plot(df['time'], df['udp_packets_sent'],
                     label=f'Node {node_id}', color=color, linewidth=1.5)

    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('UDP Packets Sent')
    ax1.set_title('UDP Packets Sent Over Time (Per Node)')
    ax1.legend(loc='upper left', ncol=2, fontsize=8)
    ax1.grid(True, alpha=0.3)

    ax2 = axes[0, 1]

    all_times = set()
    for df in data.values():
        if 'time' in df.columns:
            all_times.update(df['time'].tolist())
    times = sorted(all_times)

    total_udp = []
    for t in times:
        total = 0
        for df in data.values():
            if 'time' in df.columns and 'udp_packets_sent' in df.columns:
                mask = df['time'] <= t
                if mask.any():
                    total += df.loc[mask, 'udp_packets_sent'].iloc[-1]
        total_udp.append(total)

    ax2.plot(times, total_udp, 'g-', linewidth=2)
    ax2.fill_between(times, total_udp, alpha=0.3, color='green')
    ax2.set_xlabel('Time (s)')
    ax2.set_ylabel('Total UDP Packets Sent')
    ax2.set_title('Total Network UDP Traffic Over Time')
    ax2.grid(True, alpha=0.3)

    ax3 = axes[1, 0]
    node_ids = sorted(data.keys())

    udp_sent = []
    wca_sent = []
    received = []
    dropped = []

    for node_id in node_ids:
        df = data[node_id]
        if not df.empty:
            udp_sent.append(df['udp_packets_sent'].iloc[-1] if 'udp_packets_sent' in df.columns else 0)
            wca_sent.append(df['wca_packets_sent'].iloc[-1] if 'wca_packets_sent' in df.columns else 0)
            received.append(df['packets_received'].iloc[-1] if 'packets_received' in df.columns else 0)
            dropped.append(df['packets_dropped'].iloc[-1] if 'packets_dropped' in df.columns else 0)
        else:
            udp_sent.append(0)
            wca_sent.append(0)
            received.append(0)
            dropped.append(0)

    x = np.arange(len(node_ids))
    width = 0.2

    ax3.bar(x - 1.5*width, udp_sent, width, label='UDP Sent', color='green', alpha=0.8)
    ax3.bar(x - 0.5*width, wca_sent, width, label='WCA Sent', color='blue', alpha=0.8)
    ax3.bar(x + 0.5*width, received, width, label='Received', color='orange', alpha=0.8)
    ax3.bar(x + 1.5*width, dropped, width, label='Dropped', color='red', alpha=0.8)

    ax3.set_xticks(x)
    ax3.set_xticklabels([f'N{n}' for n in node_ids])
    ax3.set_xlabel('Node ID')
    ax3.set_ylabel('Packet Count')
    ax3.set_title('Packet Statistics Per Node')
    ax3.legend(fontsize=9)
    ax3.grid(True, axis='y', alpha=0.3)

    # Plot 4: Summary
    ax4 = axes[1, 1]
    ax4.axis('off')

    total_udp_sent = sum(udp_sent)
    total_wca_sent = sum(wca_sent)
    total_received = sum(received)
    total_dropped = sum(dropped)

    summary_text = f"""
    PACKET STATISTICS SUMMARY
    {'='*30}
    
    Total UDP packets sent: {int(total_udp_sent)}
    Total WCA packets sent: {int(total_wca_sent)}
    Total packets received: {int(total_received)}
    Total packets dropped: {int(total_dropped)}
    
    Delivery ratio: {(total_received/(total_udp_sent+0.001)*100):.1f}%
    
    Avg UDP/node: {np.mean(udp_sent):.1f}
    Avg received/node: {np.mean(received):.1f}
    """

    ax4.text(0.1, 0.9, summary_text, transform=ax4.transAxes,
             fontsize=12, verticalalignment='top', fontfamily='monospace',
             bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.8))

    plt.tight_layout()

    if output_dir:
        filepath = os.path.join(output_dir, 'udp_packets.png')
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        print(f"Saved: {filepath}")

    return fig


def create_summary_dashboard(data: dict, output_dir: str = None):
    fig = plt.figure(figsize=(16, 12))

    colors = plt.cm.tab10.colors

    all_times = set()
    for df in data.values():
        if 'time' in df.columns:
            all_times.update(df['time'].tolist())
    times = sorted(all_times)

    ax1 = fig.add_subplot(2, 2, 1)
    for node_id, df in sorted(data.items()):
        if 'time' in df.columns and 'energy_consumed' in df.columns:
            ax1.plot(df['time'], df['energy_consumed'],
                     label=f'N{node_id}', color=colors[node_id % len(colors)], linewidth=1)
    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('Energy Consumed (J)')
    ax1.set_title('1. Energy Consumption Over Time')
    ax1.legend(loc='upper left', ncol=3, fontsize=7)
    ax1.grid(True, alpha=0.3)

    ax2 = fig.add_subplot(2, 2, 2)
    for node_id, df in sorted(data.items()):
        if 'time' in df.columns and 'ch_duration_cumulative' in df.columns:
            ax2.plot(df['time'], df['ch_duration_cumulative'],
                     label=f'N{node_id}', color=colors[node_id % len(colors)], linewidth=1)
    ax2.set_xlabel('Time (s)')
    ax2.set_ylabel('Cumulative CH Duration (s)')
    ax2.set_title('2. Cluster Head Duration Over Time')
    ax2.legend(loc='upper left', ncol=3, fontsize=7)
    ax2.grid(True, alpha=0.3)

    ax3 = fig.add_subplot(2, 2, 3)

    total_reselections = []
    for t in times:
        total = 0
        for df in data.values():
            if 'ch_reselections_cumulative' in df.columns:
                mask = df['time'] <= t
                if mask.any():
                    total = max(total, df.loc[mask, 'ch_reselections_cumulative'].iloc[-1])
        total_reselections.append(total)

    ax3.plot(times, total_reselections, 'r-', linewidth=2, label='Total Reselections')
    ax3.fill_between(times, total_reselections, alpha=0.3, color='red')
    ax3.set_xlabel('Time (s)')
    ax3.set_ylabel('Cumulative Count')
    ax3.set_title('3. CH Reselections Over Time')
    ax3.legend()
    ax3.grid(True, alpha=0.3)

    ax4 = fig.add_subplot(2, 2, 4)

    total_udp = []
    for t in times:
        total = 0
        for df in data.values():
            if 'udp_packets_sent' in df.columns:
                mask = df['time'] <= t
                if mask.any():
                    total += df.loc[mask, 'udp_packets_sent'].iloc[-1]
        total_udp.append(total)

    ax4.plot(times, total_udp, 'g-', linewidth=2, label='Total UDP Sent')
    ax4.fill_between(times, total_udp, alpha=0.3, color='green')
    ax4.set_xlabel('Time (s)')
    ax4.set_ylabel('Packet Count')
    ax4.set_title('4. Total UDP Packets Sent Over Time')
    ax4.legend()
    ax4.grid(True, alpha=0.3)

    plt.suptitle('WCA Simulation Metrics Dashboard', fontsize=14, fontweight='bold')
    plt.tight_layout()

    if output_dir:
        filepath = os.path.join(output_dir, 'wca_dashboard.png')
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        print(f"Saved: {filepath}")

    return fig


def main():
    parser = argparse.ArgumentParser(description='Visualize WCA simulation metrics')
    parser.add_argument('--results-dir', type=str, default='./results',
                        help='Directory containing CSV result files')
    parser.add_argument('--output-dir', type=str, default='./plots',
                        help='Directory to save plots')

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Loading data from: {args.results_dir}")
    data = load_metrics_data(args.results_dir)

    if not data:
        print("No data found. Please check the results directory.")
        return

    print(f"\nLoaded data for {len(data)} nodes")

    print("\nGenerating plots:")

    print("Energy consumption:")
    plot_energy_consumption(data, args.output_dir)

    print("CH duration:")
    plot_ch_duration(data, args.output_dir)

    print("CH selections:")
    plot_ch_selections(data, args.output_dir)

    print("UDP packets:")
    plot_udp_packets(data, args.output_dir)

    print("Summary dashboard:")
    create_summary_dashboard(data, args.output_dir)

    print(f"\nAll plots saved to: {args.output_dir}/")
    print("Done!")


if __name__ == "__main__":
    main()