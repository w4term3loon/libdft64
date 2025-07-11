import re
import numpy as np
import matplotlib.pyplot as plt

def parse_time_output(file_path):
    """
    Parses the verbose output of the /usr/bin/time command from a given file.

    Args:
        file_path (str): The path to the file containing the time command output.

    Returns:
        dict: A dictionary where keys are the benchmarked commands (e.g., '/bin/ls')
              and values are another dictionary with 'native' and 'with_pin' results.
    """
    results = {}
    with open(file_path, 'r') as f:
        content = f.read()

    # Split the content by the "--- Timing" delimiter
    blocks = re.split(r'--- Timing (.+?) ---', content)

    # The first element is empty, so we start from the second
    i = 1
    while i < len(blocks):
        # The name of the command being timed (e.g., /bin/ls)
        command_name_full = blocks[i].strip()
        command_output = blocks[i+1]

        # Determine if this is a native run or a run with Pin
        is_with_pin = "with Pin" in command_name_full

        # Extract the base command name (e.g., /bin/ls)
        base_command = command_name_full.replace(' with Pin', '').split(' ')[0]

        if base_command not in results:
            results[base_command] = {}

        # Extract the relevant metrics using regex
        user_time_match = re.search(r'User time \(seconds\): (.+)', command_output)
        system_time_match = re.search(r'System time \(seconds\): (.+)', command_output)
        memory_match = re.search(r'Maximum resident set size \(kbytes\): (.+)', command_output)

        user_time = float(user_time_match.group(1)) if user_time_match else 0
        system_time = float(system_time_match.group(1)) if system_time_match else 0
        memory_kb = int(memory_match.group(1)) if memory_match else 0

        # Store the results
        run_type = 'with_pin' if is_with_pin else 'native'
        results[base_command][run_type] = {
            'user_time': user_time,
            'system_time': system_time,
            'memory_mb': memory_kb / 1024  # Convert to MB for easier reading
        }

        i += 2

    return results

def calculate_overhead(results):
    """
    Calculates the performance overhead (Pin - native) for each metric.

    Args:
        results (dict): The parsed results from the parse_time_output function.

    Returns:
        dict: A dictionary with overhead values for each command.
    """
    overheads = {}
    for command, runs in results.items():
        if 'native' in runs and 'with_pin' in runs:
            native = runs['native']
            with_pin = runs['with_pin']

            overheads[command] = {
                'user_time': with_pin['user_time'] - native['user_time'],
                'system_time': with_pin['system_time'] - native['system_time'],
                'memory_mb': with_pin['memory_mb'] - native['memory_mb']
            }
    return overheads

def plot_comparison(libc_overheads, libpthread_overheads, metric, title, ylabel, filename):
    """
    Generates and saves a bar chart comparing the overhead of two test runs.

    Args:
        libc_overheads (dict): Overhead data for the libc run.
        libpthread_overheads (dict): Overhead data for the libpthread run.
        metric (str): The key for the metric to plot (e.g., 'user_time').
        title (str): The title for the plot.
        ylabel (str): The label for the Y-axis.
        filename (str): The filename to save the plot to.
    """
    labels = sorted(libc_overheads.keys())
    libc_values = [libc_overheads[cmd][metric] for cmd in labels]
    libpthread_values = [libpthread_overheads[cmd][metric] for cmd in labels]

    x = np.arange(len(labels))  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots(figsize=(12, 7))
    rects1 = ax.bar(x - width/2, libc_values, width, label='libc', color='skyblue')
    rects2 = ax.bar(x + width/2, libpthread_values, width, label='libpthread', color='coral')

    # Add some text for labels, title and axes ticks
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    # Add value labels on top of the bars
    ax.bar_label(rects1, padding=3, fmt='%.2f')
    ax.bar_label(rects2, padding=3, fmt='%.2f')

    fig.tight_layout()
    plt.savefig(filename)
    print(f"Plot saved to {filename}")
    plt.close()


def main():
    """
    Main function to parse files, calculate overheads, and generate plots.
    """
    # --- File Paths ---
    # Make sure these files are in the same directory as the script,
    # or provide the full path to them.
    libc_file = 'test_results_libc.txt'
    libpthread_file = 'test_results_libpthread.txt'

    # --- Parsing and Calculation ---
    libc_results = parse_time_output(libc_file)
    libpthread_results = parse_time_output(libpthread_file)

    libc_overheads = calculate_overhead(libc_results)
    libpthread_overheads = calculate_overhead(libpthread_results)

    # --- Plotting ---
    print("Generating plots...")
    
    # Plot User Time Overhead
    plot_comparison(
        libc_overheads, 
        libpthread_overheads, 
        'user_time', 
        'User Time Overhead Comparison (Pin vs. Native)', 
        'Time (seconds)',
        'user_time_overhead.png'
    )

    # Plot System Time Overhead
    plot_comparison(
        libc_overheads, 
        libpthread_overheads, 
        'system_time', 
        'System Time Overhead Comparison (Pin vs. Native)', 
        'Time (seconds)',
        'system_time_overhead.png'
    )

    # Plot Memory Overhead
    plot_comparison(
        libc_overheads, 
        libpthread_overheads, 
        'memory_mb', 
        'Peak Memory Overhead Comparison (Pin vs. Native)', 
        'Memory (MB)',
        'memory_overhead.png'
    )

    print("\nAnalysis complete. Check the generated PNG files for the plots.")


if __name__ == '__main__':
    main()

