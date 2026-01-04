#!/usr/bin/env python3

import os
import glob
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12

def load_server_metrics(filepath):
    df = pd.read_csv(filepath, comment='#')
    return df

def load_node_metrics(results_dir):
    nodes = []
    i = 0
    while True:
        filepath = os.path.join(results_dir, f'wca_metrics_node{i}.csv')
        if os.path.exists(filepath):
            df = pd.read_csv(filepath, comment='#')
            df['node_id'] = i
            nodes.append(df)
            i += 1
        else:
            break

    if nodes:
        print(f"Loaded metrics for {len(nodes)} nodes")
        return pd.concat(nodes, ignore_index=True)
    return None

def plot_connectivity_over_time(server_df, output_path):
    plt.figure(figsize=(10, 5))
    plt.plot(server_df['time'], server_df['connected_robots'],
             'b-', linewidth=2, label='Connected Robots')
    plt.axhline(y=10, color='g', linestyle='--', label='Expected (10)')
    plt.xlabel('Time (s)')
    plt.ylabel('Number of Connected Robots')
    plt.title('Network Connectivity Over Time')
    plt.legend()
    plt.ylim(0, 12)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def plot_mode_distribution(server_df, output_path):
    plt.figure(figsize=(10, 5))

    plt.stackplot(server_df['time'],
                  server_df['direct_ap_count'],
                  server_df['gateway_count'],
                  server_df['cluster_member_count'],
                  server_df['disconnected_mode_count'],
                  labels=['DIRECT_AP', 'GATEWAY', 'CLUSTER_MEMBER', 'DISCONNECTED'],
                  colors=['#2ecc71', '#9b59b6', '#3498db', '#e74c3c'],
                  alpha=0.8)

    plt.xlabel('Time (s)')
    plt.ylabel('Number of Nodes')
    plt.title('Network Mode Distribution Over Time')
    plt.legend(loc='upper right')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def plot_mode_pie_chart(server_df, output_path):
    avg_modes = {
        'DIRECT_AP': server_df['direct_ap_count'].mean(),
        'GATEWAY': server_df['gateway_count'].mean(),
        'CLUSTER_MEMBER': server_df['cluster_member_count'].mean(),
        'DISCONNECTED': server_df['disconnected_mode_count'].mean()
    }

    # Remove zero values
    avg_modes = {k: v for k, v in avg_modes.items() if v > 0}

    plt.figure(figsize=(8, 8))
    colors = {'DIRECT_AP': '#2ecc71', 'GATEWAY': '#9b59b6',
              'CLUSTER_MEMBER': '#3498db', 'DISCONNECTED': '#e74c3c'}

    plt.pie(avg_modes.values(), labels=avg_modes.keys(),
            colors=[colors[k] for k in avg_modes.keys()],
            autopct='%1.1f%%', startangle=90)
    plt.title('Average Network Mode Distribution')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def plot_status_reports(server_df, output_path):
    plt.figure(figsize=(10, 5))
    plt.plot(server_df['time'], server_df['status_reports_received'],
             'b-', linewidth=2)
    plt.xlabel('Time (s)')
    plt.ylabel('Cumulative Status Reports')
    plt.title('Status Reports Received by Server Over Time')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def plot_energy_comparison(nodes_df, output_path):
    if nodes_df is None:
        return

    # Get final energy for each node
    final_energy = nodes_df.groupby('node_id')['energy_consumed'].last()

    plt.figure(figsize=(10, 5))
    bars = plt.bar(final_energy.index, final_energy.values, color='#3498db')
    plt.xlabel('Node ID')
    plt.ylabel('Energy Consumed (J)')
    plt.title('Total Energy Consumption per Node')
    plt.xticks(range(len(final_energy)))
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def plot_ch_time_comparison(nodes_df, output_path):
    if nodes_df is None:
        return

    # Get final CH duration for each node
    final_ch = nodes_df.groupby('node_id')['ch_duration_cumulative'].last()

    plt.figure(figsize=(10, 5))
    plt.bar(final_ch.index, final_ch.values, color='#e74c3c')
    plt.xlabel('Node ID')
    plt.ylabel('Cluster Head Duration (s)')
    plt.title('Time Spent as Cluster Head per Node')
    plt.xticks(range(len(final_ch)))
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved: {output_path}")

def generate_summary_table(server_df, nodes_df):
    print("\n" + "="*60)
    print("HWCA SIMULATION SUMMARY")
    print("="*60)

    print(f"\nSimulation Duration: {server_df['time'].max():.1f} s")
    print(f"Total Nodes: {server_df['connected_robots'].max()}")

    print("\n--- Connectivity ---")
    print(f"Average Connected: {server_df['connected_robots'].mean():.1f}")
    print(f"Min Connected: {server_df['connected_robots'].min()}")
    print(f"Connectivity Ratio: {server_df['connectivity_ratio'].mean():.1f}%")

    print("\n--- Mode Distribution (Average) ---")
    print(f"DIRECT_AP: {server_df['direct_ap_count'].mean():.1f} nodes")
    print(f"GATEWAY: {server_df['gateway_count'].mean():.1f} nodes")
    print(f"CLUSTER_MEMBER: {server_df['cluster_member_count'].mean():.1f} nodes")
    print(f"DISCONNECTED: {server_df['disconnected_mode_count'].mean():.1f} nodes")

    print("\n--- Communication ---")
    print(f"Total Status Reports: {server_df['status_reports_received'].max()}")
    print(f"Total Broadcasts: {server_df['broadcasts_sent'].max()}")

    if nodes_df is not None:
        print("\n--- Energy (per node average) ---")
        final_energy = nodes_df.groupby('node_id')['energy_consumed'].last()
        print(f"Avg Energy Consumed: {final_energy.mean():.2f} J")
        print(f"Max Energy Consumed: {final_energy.max():.2f} J")
        print(f"Min Energy Consumed: {final_energy.min():.2f} J")

    print("="*60)

def main():
    results_dir = 'results'
    output_dir = 'charts'

    os.makedirs(output_dir, exist_ok=True)

    server_file = os.path.join(results_dir, 'hwca_server_metrics.csv')
    if not os.path.exists(server_file):
        print(f"Error: {server_file} not found!")
        return

    server_df = load_server_metrics(server_file)
    nodes_df = load_node_metrics(results_dir)

    plot_connectivity_over_time(server_df, os.path.join(output_dir, 'connectivity.png'))
    plot_mode_distribution(server_df, os.path.join(output_dir, 'mode_distribution.png'))
    plot_mode_pie_chart(server_df, os.path.join(output_dir, 'mode_pie.png'))
    plot_status_reports(server_df, os.path.join(output_dir, 'status_reports.png'))

    if nodes_df is not None:
        plot_energy_comparison(nodes_df, os.path.join(output_dir, 'energy.png'))
        plot_ch_time_comparison(nodes_df, os.path.join(output_dir, 'ch_time.png'))

    generate_summary_table(server_df, nodes_df)

    print(f"\nAll charts saved to: {output_dir}/")

if __name__ == '__main__':
    main()