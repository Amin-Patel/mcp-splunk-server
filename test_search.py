"""
============================================================
FIRST SPLUNK SEARCH FROM PYTHON
============================================================
Project: MCP Server for Splunk
Author: Sayyed Abuzar (Team Lead)
Purpose: Execute SPL queries from Python and display results.

This script:
1. Connects to Splunk
2. Runs an SPL query
3. Gets the results
4. Displays them in a formatted way

This is EXACTLY what our MCP splunk_search tool will do!
Today we're testing the core logic.
============================================================
"""

import splunklib.results as results    # For parsing search results
import json                            # For formatting output
import time                            # For tracking search duration
from splunk_config import connect_to_splunk, get_splunk_config


def run_splunk_search(query, earliest_time="-24h", latest_time="now"):
    """
    Execute an SPL query on Splunk and return results.
    
    Parameters:
        query (str): The SPL query to execute
                     Example: "index=_internal | head 10"
        earliest_time (str): Start of time range
                            "-24h" = last 24 hours
                            "-1h"  = last 1 hour
                            "-7d"  = last 7 days
        latest_time (str): End of time range
                          "now" = current time
    
    Returns:
        list: A list of dictionaries, each representing one result row
    
    How Splunk search works:
    1. We CREATE a search job (tell Splunk to start searching)
    2. We WAIT for the job to finish (Splunk processes data)
    3. We READ the results (get the answer)
    
    It's like ordering food at a restaurant:
    1. Place order (create job)
    2. Wait for cooking (job processing)
    3. Food arrives (read results)
    """
    
    # Step 1: Connect to Splunk
    service = connect_to_splunk()
    
    # Step 2: Set up search parameters
    search_params = {
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "search_mode": "normal",     # "normal" or "realtime"
        "count": 0,                  # 0 = return ALL results
    }
    
    # Step 3: Make sure query starts with "search" command
    # Splunk requires this for the SDK
    if not query.startswith("|") and not query.startswith("search"):
        query = f"search {query}"
    
    print(f"🔍 Query: {query}")
    print(f"⏰ Time range: {earliest_time} → {latest_time}")
    print(f"⏳ Executing search...")
    
    # Track how long the search takes
    start_time = time.time()
    
    # Step 4: Create and run the search job
    job = service.jobs.create(query, **search_params)
    
    # Step 5: Wait for the job to complete
    # Splunk searches can take time, especially on large datasets
    while not job.is_done():
        time.sleep(0.5)  # Check every 0.5 seconds
        # Print progress dots
        print(".", end="", flush=True)
    
    # Calculate search duration
    duration = round(time.time() - start_time, 2)
    print(f"\n✅ Search completed in {duration} seconds")
    
    # Step 6: Get the result count
    result_count = int(job["resultCount"])
    print(f"📊 Results found: {result_count}")
    
    # Step 7: Read and parse results
    result_list = []
    result_reader = results.JSONResultsReader(job.results(output_mode="json"))
    
    for item in result_reader:
        if isinstance(item, results.Message):
            # This is a message from Splunk (warning, info, etc.)
            print(f"   ℹ️  Splunk message: {item.message}")
        elif isinstance(item, dict):
            # This is an actual result row
            result_list.append(item)
    
    # Step 8: Clean up — cancel the job to free Splunk resources
    job.cancel()
    
    return result_list


def print_results(result_list, max_results=10):
    """
    Print search results in a nice formatted way.
    
    Parameters:
        result_list (list): List of result dictionaries
        max_results (int): Maximum number of results to display
    """
    if not result_list:
        print("\n📭 No results found.")
        return
    
    print(f"\n{'='*60}")
    print(f"  SEARCH RESULTS (showing {min(len(result_list), max_results)} of {len(result_list)})")
    print(f"{'='*60}")
    
    for i, row in enumerate(result_list[:max_results]):
        print(f"\n--- Result #{i+1} ---")
        for key, value in row.items():
            # Skip internal fields that start with _
            # (unless it's _time which is useful)
            if key.startswith("_") and key != "_time":
                continue
            print(f"  {key}: {value}")
    
    if len(result_list) > max_results:
        print(f"\n... and {len(result_list) - max_results} more results")
    
    print(f"\n{'='*60}")


def main():
    """
    Run multiple test searches to verify everything works.
    """
    print("\n" + "="*60)
    print("  MCP-SPLUNK PROJECT — SEARCH TEST")
    print("="*60)
    
    # ========================================
    # TEST 1: Basic search — get recent events
    # ========================================
    print("\n\n📌 TEST 1: Get 5 most recent internal events")
    print("-" * 50)
    
    query1 = "index=_internal | head 5"
    results1 = run_splunk_search(query1, earliest_time="-1h")
    print_results(results1)
    
    # ========================================
    # TEST 2: Stats query — count by sourcetype
    # ========================================
    print("\n\n📌 TEST 2: Count events by source type")
    print("-" * 50)
    
    query2 = "index=_internal | stats count by sourcetype | sort - count | head 5"
    results2 = run_splunk_search(query2, earliest_time="-24h")
    print_results(results2)
    
    # ========================================
    # TEST 3: Time chart — events per hour
    # ========================================
    print("\n\n📌 TEST 3: Events per hour (last 6 hours)")
    print("-" * 50)
    
    query3 = "index=_internal | timechart span=1h count"
    results3 = run_splunk_search(query3, earliest_time="-6h")
    print_results(results3)
    
    # ========================================
    # TEST 4: Summary statistics
    # ========================================
    print("\n\n📌 TEST 4: Summary statistics")
    print("-" * 50)
    
    query4 = """index=_internal 
    | stats count as total_events,
            dc(sourcetype) as unique_sourcetypes,
            dc(source) as unique_sources"""
    results4 = run_splunk_search(query4, earliest_time="-24h")
    print_results(results4)
    
    # ========================================
    # FINAL SUMMARY
    # ========================================
    print("\n\n" + "="*60)
    all_passed = all([results1, results2, results3, results4])
    
    if all_passed:
        print("""
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║  🎉 ALL 4 SEARCH TESTS PASSED!                     ║
  ║                                                      ║
  ║  Your Python code can now:                          ║
  ║  ✅ Connect to Splunk                               ║
  ║  ✅ Execute SPL queries                             ║
  ║  ✅ Get and parse results                           ║
  ║  ✅ Handle different query types                    ║
  ║                                                      ║
  ║  This is the FOUNDATION of your MCP Server!         ║
  ║  In Week 3, we'll wrap this in MCP tools!           ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
        """)
    else:
        print("  ⚠️ Some tests didn't return results. Check the errors above.")
    
    print("="*60 + "\n")


# Run the tests when this file is executed directly
if __name__ == "__main__":
    main()